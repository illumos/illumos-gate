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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * String conversion routine for .dynamic tag entries.
 */
#include	<stdio.h>
#include	<string.h>
#include	<sys/elf_SPARC.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"dynamic_msg.h"



const Val_desc *
conv_dyn_posflag1_strings(Conv_fmt_flags_t fmt_flags)
{
#define	POSSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_DF_P1_LAZYLOAD_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_P1_GROUPPERM_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_P1_DEFERRED_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_dyn_posflag1_buf_t is large enough:
	 *
	 * POSSZ is the real minimum size of the buffer required by
	 * conv_dyn_posflag1(). However, Conv_dyn_posflag1_buf_t uses
	 * CONV_DYN_POSFLAG1_BUFSIZE to set the buffer size. We do things
	 * this way because the definition of POSSZ uses
	 * information that is not available in the environment of other
	 * programs that include the conv.h header file.
	 */
#if (CONV_DYN_POSFLAG1_BUFSIZE != POSSZ) && !defined(__lint)
#define	REPORT_BUFSIZE POSSZ
#include "report_bufsize.h"
#error "CONV_DYN_POSFLAG1_BUFSIZE does not match POSSZ"
#endif

	static const Val_desc vda_def[] = {
		{ DF_P1_LAZYLOAD,	MSG_DF_P1_LAZYLOAD_DEF },
		{ DF_P1_GROUPPERM,	MSG_DF_P1_GROUPPERM_DEF },
		{ DF_P1_DEFERRED,	MSG_DF_P1_DEFERRED_DEF },
		{ 0,			0 }
	};
	static const Val_desc vda_cf[] = {
		{ DF_P1_LAZYLOAD,	MSG_DF_P1_LAZYLOAD_CF },
		{ DF_P1_GROUPPERM,	MSG_DF_P1_GROUPPERM_CF },
		{ DF_P1_DEFERRED,	MSG_DF_P1_DEFERRED_CF },
		{ 0,			0 }
	};
	static const Val_desc vda_cfnp[] = {
		{ DF_P1_LAZYLOAD,	MSG_DF_P1_LAZYLOAD_CFNP },
		{ DF_P1_GROUPPERM,	MSG_DF_P1_GROUPPERM_CFNP },
		{ DF_P1_DEFERRED,	MSG_DF_P1_DEFERRED_CFNP },
		{ 0,			0 }
	};
	static const Val_desc vda_nf[] = {
		{ DF_P1_LAZYLOAD,	MSG_DF_P1_LAZYLOAD_NF },
		{ DF_P1_GROUPPERM,	MSG_DF_P1_GROUPPERM_NF },
		{ DF_P1_DEFERRED,	MSG_DF_P1_DEFERRED_NF },
		{ 0,			0 }
	};

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_CFNP:
		return (vda_cfnp);
	case CONV_FMT_ALT_CF:
		return (vda_cf);
	case CONV_FMT_ALT_NF:
		return (vda_nf);
	}

	return (vda_def);
}

conv_iter_ret_t
conv_iter_dyn_posflag1(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_vd(conv_dyn_posflag1_strings(fmt_flags),
	    func, uvalue));
}

const Val_desc *
conv_dyn_flag_strings(Conv_fmt_flags_t fmt_flags)
{
#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_DF_ORIGIN_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_SYMBOLIC_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_TEXTREL_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_BIND_NOW_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_STATIC_TLS_CF_SIZE 	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_dyn_flag_buf_t is large enough:
	 *
	 * FLAGSZ is the real minimum size of the buffer required by
	 * conv_dyn_flag(). However, Conv_dyn_flag_buf_t uses
	 * CONV_DYN_FLAG_BUFSIZE to set the buffer size. We do things this
	 * way because the definition of FLAGSZ uses information that is not
	 * available in the environment of other programs that include the
	 * conv.h header file.
	 */
#if (CONV_DYN_FLAG_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_DYN_FLAG_BUFSIZE does not match FLAGSZ"
#endif

	static const Val_desc vda_cf[] = {
		{ DF_ORIGIN,		MSG_DF_ORIGIN_CF },
		{ DF_SYMBOLIC,		MSG_DF_SYMBOLIC_CF },
		{ DF_TEXTREL,		MSG_DF_TEXTREL_CF },
		{ DF_BIND_NOW,		MSG_DF_BIND_NOW_CF },
		{ DF_STATIC_TLS,	MSG_DF_STATIC_TLS_CF },
		{ 0 }
	};
	static const Val_desc vda_cfnp[] = {
		{ DF_ORIGIN,		MSG_DF_ORIGIN_CFNP },
		{ DF_SYMBOLIC,		MSG_DF_SYMBOLIC_CFNP },
		{ DF_TEXTREL,		MSG_DF_TEXTREL_CFNP },
		{ DF_BIND_NOW,		MSG_DF_BIND_NOW_CFNP },
		{ DF_STATIC_TLS,	MSG_DF_STATIC_TLS_CFNP },
		{ 0 }
	};
	static const Val_desc vda_nf[] = {
		{ DF_ORIGIN,		MSG_DF_ORIGIN_NF },
		{ DF_SYMBOLIC,		MSG_DF_SYMBOLIC_NF },
		{ DF_TEXTREL,		MSG_DF_TEXTREL_NF },
		{ DF_BIND_NOW,		MSG_DF_BIND_NOW_NF },
		{ DF_STATIC_TLS,	MSG_DF_STATIC_TLS_NF },
		{ 0 }
	};

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (vda_cf);
	case CONV_FMT_ALT_NF:
		return (vda_nf);
	}

	return (vda_cfnp);
}

conv_iter_ret_t
conv_iter_dyn_flag(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_vd(conv_dyn_flag_strings(fmt_flags), func, uvalue));
}

const Val_desc *
conv_dyn_flag1_strings(Conv_fmt_flags_t fmt_flags)
{
#define	FLAG1SZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_DF_1_NOW_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_GLOBAL_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_GROUP_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NODELETE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_LOADFLTR_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_INITFIRST_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NOOPEN_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_ORIGIN_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_DIRECT_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_TRANS_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_INTERPOSE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NODEFLIB_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NODUMP_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_CONFALT_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_ENDFILTEE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_DISPRELPND_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_DISPRELDNE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NODIRECT_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_IGNMULDEF_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NOKSYMS_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NOHDR_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_NORELOC_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_SYMINTPOSE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_GLOBAUDIT_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DF_1_SINGLETON_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_dyn_flag1_buf_t is large enough:
	 *
	 * FLAG1SZ is the real minimum size of the buffer required by
	 * conv_dyn_flag1(). However, Conv_dyn_flag1_buf_t uses
	 * CONV_DYN_FLAG1_BUFSIZE to set the buffer size. We do things this
	 * way because the definition of FLAG1SZ uses information that is not
	 * available in the environment of other programs that include the
	 * conv.h header file.
	 */
#if (CONV_DYN_FLAG1_BUFSIZE != FLAG1SZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAG1SZ
#include "report_bufsize.h"
#error "CONV_DYN_FLAG1_BUFSIZE does not match FLAG1SZ"
#endif

	static const Val_desc vda_def[] = {
		{ DF_1_NOW,		MSG_DF_1_NOW_CFNP },
		{ DF_1_GLOBAL,		MSG_DF_1_GLOBAL_CFNP },
		{ DF_1_GROUP,		MSG_DF_1_GROUP_CFNP },
		{ DF_1_NODELETE,	MSG_DF_1_NODELETE_CFNP },
		{ DF_1_LOADFLTR,	MSG_DF_1_LOADFLTR_CFNP },
		{ DF_1_INITFIRST,	MSG_DF_1_INITFIRST_CFNP },
		{ DF_1_NOOPEN,		MSG_DF_1_NOOPEN_CFNP },
		{ DF_1_ORIGIN,		MSG_DF_1_ORIGIN_CFNP },
		{ DF_1_DIRECT,		MSG_DF_1_DIRECT_CFNP },
		{ DF_1_TRANS,		MSG_DF_1_TRANS_CFNP },
		{ DF_1_INTERPOSE,	MSG_DF_1_INTERPOSE_DEF },
		{ DF_1_NODEFLIB,	MSG_DF_1_NODEFLIB_CFNP },
		{ DF_1_NODUMP,		MSG_DF_1_NODUMP_CFNP },
		{ DF_1_CONFALT,		MSG_DF_1_CONFALT_CFNP },
		{ DF_1_ENDFILTEE,	MSG_DF_1_ENDFILTEE_CFNP },
		{ DF_1_DISPRELDNE,	MSG_DF_1_DISPRELDNE_DEF },
		{ DF_1_DISPRELPND,	MSG_DF_1_DISPRELPND_DEF },
		{ DF_1_NODIRECT,	MSG_DF_1_NODIRECT_CFNP },
		{ DF_1_IGNMULDEF,	MSG_DF_1_IGNMULDEF_DEF },
		{ DF_1_NOKSYMS,		MSG_DF_1_NOKSYMS_CFNP },
		{ DF_1_NOHDR,		MSG_DF_1_NOHDR_CFNP },
		{ DF_1_EDITED,		MSG_DF_1_EDITED_CFNP },
		{ DF_1_NORELOC,		MSG_DF_1_NORELOC_CFNP },
		{ DF_1_SYMINTPOSE,	MSG_DF_1_SYMINTPOSE_DEF },
		{ DF_1_GLOBAUDIT,	MSG_DF_1_GLOBAUDIT_DEF },
		{ DF_1_SINGLETON,	MSG_DF_1_SINGLETON_DEF },
		{ 0,			0 }
	};
	static const Val_desc vda_cf[] = {
		{ DF_1_NOW,		MSG_DF_1_NOW_CF },
		{ DF_1_GLOBAL,		MSG_DF_1_GLOBAL_CF },
		{ DF_1_GROUP,		MSG_DF_1_GROUP_CF },
		{ DF_1_NODELETE,	MSG_DF_1_NODELETE_CF },
		{ DF_1_LOADFLTR,	MSG_DF_1_LOADFLTR_CF },
		{ DF_1_INITFIRST,	MSG_DF_1_INITFIRST_CF },
		{ DF_1_NOOPEN,		MSG_DF_1_NOOPEN_CF },
		{ DF_1_ORIGIN,		MSG_DF_1_ORIGIN_CF },
		{ DF_1_DIRECT,		MSG_DF_1_DIRECT_CF },
		{ DF_1_TRANS,		MSG_DF_1_TRANS_CF },
		{ DF_1_INTERPOSE,	MSG_DF_1_INTERPOSE_CF },
		{ DF_1_NODEFLIB,	MSG_DF_1_NODEFLIB_CF },
		{ DF_1_NODUMP,		MSG_DF_1_NODUMP_CF },
		{ DF_1_CONFALT,		MSG_DF_1_CONFALT_CF },
		{ DF_1_ENDFILTEE,	MSG_DF_1_ENDFILTEE_CF },
		{ DF_1_DISPRELDNE,	MSG_DF_1_DISPRELDNE_CF },
		{ DF_1_DISPRELPND,	MSG_DF_1_DISPRELPND_CF },
		{ DF_1_NODIRECT,	MSG_DF_1_NODIRECT_CF },
		{ DF_1_IGNMULDEF,	MSG_DF_1_IGNMULDEF_CF },
		{ DF_1_NOKSYMS,		MSG_DF_1_NOKSYMS_CF },
		{ DF_1_NOHDR,		MSG_DF_1_NOHDR_CF },
		{ DF_1_EDITED,		MSG_DF_1_EDITED_CF },
		{ DF_1_NORELOC,		MSG_DF_1_NORELOC_CF },
		{ DF_1_SYMINTPOSE,	MSG_DF_1_SYMINTPOSE_CF },
		{ DF_1_GLOBAUDIT,	MSG_DF_1_GLOBAUDIT_CF },
		{ DF_1_SINGLETON,	MSG_DF_1_SINGLETON_CF },
		{ 0,			0 }
	};
	static const Val_desc vda_cfnp[] = {
		{ DF_1_NOW,		MSG_DF_1_NOW_CFNP },
		{ DF_1_GLOBAL,		MSG_DF_1_GLOBAL_CFNP },
		{ DF_1_GROUP,		MSG_DF_1_GROUP_CFNP },
		{ DF_1_NODELETE,	MSG_DF_1_NODELETE_CFNP },
		{ DF_1_LOADFLTR,	MSG_DF_1_LOADFLTR_CFNP },
		{ DF_1_INITFIRST,	MSG_DF_1_INITFIRST_CFNP },
		{ DF_1_NOOPEN,		MSG_DF_1_NOOPEN_CFNP },
		{ DF_1_ORIGIN,		MSG_DF_1_ORIGIN_CFNP },
		{ DF_1_DIRECT,		MSG_DF_1_DIRECT_CFNP },
		{ DF_1_TRANS,		MSG_DF_1_TRANS_CFNP },
		{ DF_1_INTERPOSE,	MSG_DF_1_INTERPOSE_CFNP },
		{ DF_1_NODEFLIB,	MSG_DF_1_NODEFLIB_CFNP },
		{ DF_1_NODUMP,		MSG_DF_1_NODUMP_CFNP },
		{ DF_1_CONFALT,		MSG_DF_1_CONFALT_CFNP },
		{ DF_1_ENDFILTEE,	MSG_DF_1_ENDFILTEE_CFNP },
		{ DF_1_DISPRELDNE,	MSG_DF_1_DISPRELDNE_CFNP },
		{ DF_1_DISPRELPND,	MSG_DF_1_DISPRELPND_CFNP },
		{ DF_1_NODIRECT,	MSG_DF_1_NODIRECT_CFNP },
		{ DF_1_IGNMULDEF,	MSG_DF_1_IGNMULDEF_CFNP },
		{ DF_1_NOKSYMS,		MSG_DF_1_NOKSYMS_CFNP },
		{ DF_1_NOHDR,		MSG_DF_1_NOHDR_CFNP },
		{ DF_1_EDITED,		MSG_DF_1_EDITED_CFNP },
		{ DF_1_NORELOC,		MSG_DF_1_NORELOC_CFNP },
		{ DF_1_SYMINTPOSE,	MSG_DF_1_SYMINTPOSE_CFNP },
		{ DF_1_GLOBAUDIT,	MSG_DF_1_GLOBAUDIT_CFNP },
		{ DF_1_SINGLETON,	MSG_DF_1_SINGLETON_CFNP },
		{ 0,			0 }
	};
	static const Val_desc vda_nf[] = {
		{ DF_1_NOW,		MSG_DF_1_NOW_NF },
		{ DF_1_GLOBAL,		MSG_DF_1_GLOBAL_NF },
		{ DF_1_GROUP,		MSG_DF_1_GROUP_NF },
		{ DF_1_NODELETE,	MSG_DF_1_NODELETE_NF },
		{ DF_1_LOADFLTR,	MSG_DF_1_LOADFLTR_NF },
		{ DF_1_INITFIRST,	MSG_DF_1_INITFIRST_NF },
		{ DF_1_NOOPEN,		MSG_DF_1_NOOPEN_NF },
		{ DF_1_ORIGIN,		MSG_DF_1_ORIGIN_NF },
		{ DF_1_DIRECT,		MSG_DF_1_DIRECT_NF },
		{ DF_1_TRANS,		MSG_DF_1_TRANS_NF },
		{ DF_1_INTERPOSE,	MSG_DF_1_INTERPOSE_NF },
		{ DF_1_NODEFLIB,	MSG_DF_1_NODEFLIB_NF },
		{ DF_1_NODUMP,		MSG_DF_1_NODUMP_NF },
		{ DF_1_CONFALT,		MSG_DF_1_CONFALT_NF },
		{ DF_1_ENDFILTEE,	MSG_DF_1_ENDFILTEE_NF },
		{ DF_1_DISPRELDNE,	MSG_DF_1_DISPRELDNE_NF },
		{ DF_1_DISPRELPND,	MSG_DF_1_DISPRELPND_NF },
		{ DF_1_NODIRECT,	MSG_DF_1_NODIRECT_NF },
		{ DF_1_IGNMULDEF,	MSG_DF_1_IGNMULDEF_NF },
		{ DF_1_NOKSYMS,		MSG_DF_1_NOKSYMS_NF },
		{ DF_1_NOHDR,		MSG_DF_1_NOHDR_NF },
		{ DF_1_EDITED,		MSG_DF_1_EDITED_NF },
		{ DF_1_NORELOC,		MSG_DF_1_NORELOC_NF },
		{ DF_1_SYMINTPOSE,	MSG_DF_1_SYMINTPOSE_NF },
		{ DF_1_GLOBAUDIT,	MSG_DF_1_GLOBAUDIT_NF },
		{ DF_1_SINGLETON,	MSG_DF_1_SINGLETON_NF },
		{ 0,			0 }
	};

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (vda_cf);
	case CONV_FMT_ALT_CFNP:
		return (vda_cfnp);
	case CONV_FMT_ALT_NF:
		return (vda_nf);
	}

	return (vda_def);
}

conv_iter_ret_t
conv_iter_dyn_flag1(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_vd(conv_dyn_flag1_strings(fmt_flags), func, uvalue));
}

const Val_desc *
conv_dyn_feature1_strings(Conv_fmt_flags_t fmt_flags)
{
#define	FEATSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_DTF_1_PARINIT_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_DTF_1_CONFEXP_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_dyn_feature1_buf_t is large enough:
	 *
	 * FEATSZ is the real min size of the buffer required by
	 * conv_dyn_feature1(). However, Conv_dyn_feature1_buf_t uses
	 * CONV_DYN_FEATURE1_BUFSIZE to set the buffer size. We do things
	 * this way because the definition of FEATSZ uses information that
	 * is not available in the environment of other programs that include
	 * the conv.h header file.
	 */
#if (CONV_DYN_FEATURE1_BUFSIZE != FEATSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FEATSZ
#include "report_bufsize.h"
#error "CONV_DYN_FEATURE1_BUFSIZE does not match FEATSZ"
#endif

	static const Val_desc vda_cf[] = {
		{ DTF_1_PARINIT,	MSG_DTF_1_PARINIT_CF },
		{ DTF_1_CONFEXP,	MSG_DTF_1_CONFEXP_CF },
		{ 0,			0 }
	};
	static const Val_desc vda_cfnp[] = {
		{ DTF_1_PARINIT,	MSG_DTF_1_PARINIT_CFNP },
		{ DTF_1_CONFEXP,	MSG_DTF_1_CONFEXP_CFNP },
		{ 0,			0 }
	};
	static const Val_desc vda_nf[] = {
		{ DTF_1_PARINIT,	MSG_DTF_1_PARINIT_NF },
		{ DTF_1_CONFEXP,	MSG_DTF_1_CONFEXP_NF },
		{ 0,			0 }
	};

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (vda_cf);
	case CONV_FMT_ALT_NF:
		return (vda_nf);
	}

	return (vda_cfnp);
}

conv_iter_ret_t
conv_iter_dyn_feature1(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_vd(conv_dyn_feature1_strings(fmt_flags),
	    func, uvalue));
}

const conv_ds_t **
conv_dyn_tag_strings(conv_iter_osabi_t osabi, Half mach,
    Conv_fmt_flags_t fmt_flags)
{
	/*
	 * Maximum # of items that can be in the returned array. Size this
	 * by counting the maximum depth in the switch statement that fills
	 * retarr at the end of this function.
	 */
#define	MAX_RET	12

	/*
	 * Generic dynamic tags:
	 * -	Note hole between DT_FLAGS and DT_PREINIT_ARRAY (tag 32).
	 *	We use a 0, which is the signal for "not defined".
	 * -	This range has alternative names for dump, requiring an
	 *	additional array.
	 */
	static const Msg	tags_null_cf[] = {
		MSG_DT_NULL_CF,			MSG_DT_NEEDED_CF,
		MSG_DT_PLTRELSZ_CF,		MSG_DT_PLTGOT_CF,
		MSG_DT_HASH_CF,			MSG_DT_STRTAB_CF,
		MSG_DT_SYMTAB_CF,		MSG_DT_RELA_CF,
		MSG_DT_RELASZ_CF,		MSG_DT_RELAENT_CF,
		MSG_DT_STRSZ_CF,		MSG_DT_SYMENT_CF,
		MSG_DT_INIT_CF,			MSG_DT_FINI_CF,
		MSG_DT_SONAME_CF,		MSG_DT_RPATH_CF,
		MSG_DT_SYMBOLIC_CF,		MSG_DT_REL_CF,
		MSG_DT_RELSZ_CF,		MSG_DT_RELENT_CF,
		MSG_DT_PLTREL_CF,		MSG_DT_DEBUG_CF,
		MSG_DT_TEXTREL_CF,		MSG_DT_JMPREL_CF,
		MSG_DT_BIND_NOW_CF,		MSG_DT_INIT_ARRAY_CF,
		MSG_DT_FINI_ARRAY_CF,		MSG_DT_INIT_ARRAYSZ_CF,
		MSG_DT_FINI_ARRAYSZ_CF,		MSG_DT_RUNPATH_CF,
		MSG_DT_FLAGS_CF,		0,
		MSG_DT_PREINIT_ARRAY_CF,	MSG_DT_PREINIT_ARRAYSZ_CF
	};
	static const Msg	tags_null_cfnp[] = {
		MSG_DT_NULL_CFNP,		MSG_DT_NEEDED_CFNP,
		MSG_DT_PLTRELSZ_CFNP,		MSG_DT_PLTGOT_CFNP,
		MSG_DT_HASH_CFNP,		MSG_DT_STRTAB_CFNP,
		MSG_DT_SYMTAB_CFNP,		MSG_DT_RELA_CFNP,
		MSG_DT_RELASZ_CFNP,		MSG_DT_RELAENT_CFNP,
		MSG_DT_STRSZ_CFNP,		MSG_DT_SYMENT_CFNP,
		MSG_DT_INIT_CFNP,		MSG_DT_FINI_CFNP,
		MSG_DT_SONAME_CFNP,		MSG_DT_RPATH_CFNP,
		MSG_DT_SYMBOLIC_CFNP,		MSG_DT_REL_CFNP,
		MSG_DT_RELSZ_CFNP,		MSG_DT_RELENT_CFNP,
		MSG_DT_PLTREL_CFNP,		MSG_DT_DEBUG_CFNP,
		MSG_DT_TEXTREL_CFNP,		MSG_DT_JMPREL_CFNP,
		MSG_DT_BIND_NOW_CFNP,		MSG_DT_INIT_ARRAY_CFNP,
		MSG_DT_FINI_ARRAY_CFNP,		MSG_DT_INIT_ARRAYSZ_CFNP,
		MSG_DT_FINI_ARRAYSZ_CFNP,	MSG_DT_RUNPATH_CFNP,
		MSG_DT_FLAGS_CFNP,		0,
		MSG_DT_PREINIT_ARRAY_CFNP,	MSG_DT_PREINIT_ARRAYSZ_CFNP
	};
	static const Msg	tags_null_nf[] = {
		MSG_DT_NULL_NF,			MSG_DT_NEEDED_NF,
		MSG_DT_PLTRELSZ_NF,		MSG_DT_PLTGOT_NF,
		MSG_DT_HASH_NF,			MSG_DT_STRTAB_NF,
		MSG_DT_SYMTAB_NF,		MSG_DT_RELA_NF,
		MSG_DT_RELASZ_NF,		MSG_DT_RELAENT_NF,
		MSG_DT_STRSZ_NF,		MSG_DT_SYMENT_NF,
		MSG_DT_INIT_NF,			MSG_DT_FINI_NF,
		MSG_DT_SONAME_NF,		MSG_DT_RPATH_NF,
		MSG_DT_SYMBOLIC_NF,		MSG_DT_REL_NF,
		MSG_DT_RELSZ_NF,		MSG_DT_RELENT_NF,
		MSG_DT_PLTREL_NF,		MSG_DT_DEBUG_NF,
		MSG_DT_TEXTREL_NF,		MSG_DT_JMPREL_NF,
		MSG_DT_BIND_NOW_NF,		MSG_DT_INIT_ARRAY_NF,
		MSG_DT_FINI_ARRAY_NF,		MSG_DT_INIT_ARRAYSZ_NF,
		MSG_DT_FINI_ARRAYSZ_NF,		MSG_DT_RUNPATH_NF,
		MSG_DT_FLAGS_NF,		0,
		MSG_DT_PREINIT_ARRAY_NF,	MSG_DT_PREINIT_ARRAYSZ_NF
	};
	static const Msg	tags_null_dmp[] = {
		MSG_DT_NULL_CFNP,		MSG_DT_NEEDED_CFNP,
		MSG_DT_PLTRELSZ_DMP,		MSG_DT_PLTGOT_CFNP,
		MSG_DT_HASH_CFNP,		MSG_DT_STRTAB_CFNP,
		MSG_DT_SYMTAB_CFNP,		MSG_DT_RELA_CFNP,
		MSG_DT_RELASZ_CFNP,		MSG_DT_RELAENT_CFNP,
		MSG_DT_STRSZ_CFNP,		MSG_DT_SYMENT_CFNP,
		MSG_DT_INIT_CFNP,		MSG_DT_FINI_CFNP,
		MSG_DT_SONAME_CFNP,		MSG_DT_RPATH_CFNP,
		MSG_DT_SYMBOLIC_DMP,		MSG_DT_REL_CFNP,
		MSG_DT_RELSZ_CFNP,		MSG_DT_RELENT_CFNP,
		MSG_DT_PLTREL_CFNP,		MSG_DT_DEBUG_CFNP,
		MSG_DT_TEXTREL_CFNP,		MSG_DT_JMPREL_CFNP,
		MSG_DT_BIND_NOW_CFNP,		MSG_DT_INIT_ARRAY_CFNP,
		MSG_DT_FINI_ARRAY_CFNP,		MSG_DT_INIT_ARRAYSZ_CFNP,
		MSG_DT_FINI_ARRAYSZ_CFNP,	MSG_DT_RUNPATH_CFNP,
		MSG_DT_FLAGS_CFNP,		0,
		MSG_DT_PREINIT_ARRAY_CFNP,	MSG_DT_PREINIT_ARRAYSZ_CFNP
	};
	static const conv_ds_msg_t ds_null_cf = {
	    CONV_DS_MSG_INIT(DT_NULL, tags_null_cf) };
	static const conv_ds_msg_t ds_null_cfnp = {
	    CONV_DS_MSG_INIT(DT_NULL, tags_null_cfnp) };
	static const conv_ds_msg_t ds_null_nf = {
	    CONV_DS_MSG_INIT(DT_NULL, tags_null_nf) };
	static const conv_ds_msg_t ds_null_dmp = {
	    CONV_DS_MSG_INIT(DT_NULL, tags_null_dmp) };

	/*
	 * DT_SPARC_REGISTER was originally assigned 0x7000001. It is processor
	 * specific, and should have been in the range DT_LOPROC-DT_HIPROC
	 * instead of here. When the error was fixed,
	 * DT_DEPRECATED_SPARC_REGISTER was created to maintain backward
	 * compatability.
	 */
	static const Msg	tags_sdreg_cf[] = {
	    MSG_DT_DEP_SPARC_REG_CF };
	static const Msg	tags_sdreg_cfnp[] = {
	    MSG_DT_DEP_SPARC_REG_CFNP };
	static const Msg	tags_sdreg_nf[] = {
	    MSG_DT_DEP_SPARC_REG_NF };

	static const conv_ds_msg_t ds_sdreg_cf = {
	    CONV_DS_MSG_INIT(DT_DEPRECATED_SPARC_REGISTER, tags_sdreg_cf) };
	static const conv_ds_msg_t ds_sdreg_cfnp = {
	    CONV_DS_MSG_INIT(DT_DEPRECATED_SPARC_REGISTER, tags_sdreg_cfnp) };
	static const conv_ds_msg_t ds_sdreg_nf = {
	    CONV_DS_MSG_INIT(DT_DEPRECATED_SPARC_REGISTER, tags_sdreg_nf) };


	/*
	 * SUNW: DT_LOOS -> DT_HIOS range. Note holes between DT_SUNW_TLSSORTSZ,
	 * DT_SUNW_STRPAD, and DT_SUNW_LDMACH. We handle the outliers
	 * separately below as single values.
	 */
	static const Msg	tags_sunw_auxiliary_cf[] = {
		MSG_DT_SUNW_AUXILIARY_CF,	MSG_DT_SUNW_RTLDINF_CF,
		MSG_DT_SUNW_FILTER_CF,		MSG_DT_SUNW_CAP_CF,
		MSG_DT_SUNW_SYMTAB_CF,		MSG_DT_SUNW_SYMSZ_CF,
		MSG_DT_SUNW_SORTENT_CF,		MSG_DT_SUNW_SYMSORT_CF,
		MSG_DT_SUNW_SYMSORTSZ_CF,	MSG_DT_SUNW_TLSSORT_CF,
		MSG_DT_SUNW_TLSSORTSZ_CF,	MSG_DT_SUNW_CAPINFO_CF,
		MSG_DT_SUNW_STRPAD_CF,		MSG_DT_SUNW_CAPCHAIN_CF,
		MSG_DT_SUNW_LDMACH_CF,		0,
		MSG_DT_SUNW_CAPCHAINENT_CF,	0,
		MSG_DT_SUNW_CAPCHAINSZ_CF,	0,
		0, 				0,
		MSG_DT_SUNW_ASLR_CF
	};
	static const Msg	tags_sunw_auxiliary_cfnp[] = {
		MSG_DT_SUNW_AUXILIARY_CFNP,	MSG_DT_SUNW_RTLDINF_CFNP,
		MSG_DT_SUNW_FILTER_CFNP,	MSG_DT_SUNW_CAP_CFNP,
		MSG_DT_SUNW_SYMTAB_CFNP,	MSG_DT_SUNW_SYMSZ_CFNP,
		MSG_DT_SUNW_SORTENT_CFNP,	MSG_DT_SUNW_SYMSORT_CFNP,
		MSG_DT_SUNW_SYMSORTSZ_CFNP,	MSG_DT_SUNW_TLSSORT_CFNP,
		MSG_DT_SUNW_TLSSORTSZ_CFNP,	MSG_DT_SUNW_CAPINFO_CFNP,
		MSG_DT_SUNW_STRPAD_CFNP,	MSG_DT_SUNW_CAPCHAIN_CFNP,
		MSG_DT_SUNW_LDMACH_CFNP,	0,
		MSG_DT_SUNW_CAPCHAINENT_CFNP,	0,
		MSG_DT_SUNW_CAPCHAINSZ_CFNP,	0,
		0,				0,
		MSG_DT_SUNW_ASLR_CFNP
	};
	static const Msg	tags_sunw_auxiliary_nf[] = {
		MSG_DT_SUNW_AUXILIARY_NF,	MSG_DT_SUNW_RTLDINF_NF,
		MSG_DT_SUNW_FILTER_NF,		MSG_DT_SUNW_CAP_NF,
		MSG_DT_SUNW_SYMTAB_NF,		MSG_DT_SUNW_SYMSZ_NF,
		MSG_DT_SUNW_SORTENT_NF,		MSG_DT_SUNW_SYMSORT_NF,
		MSG_DT_SUNW_SYMSORTSZ_NF,	MSG_DT_SUNW_TLSSORT_NF,
		MSG_DT_SUNW_TLSSORTSZ_NF,	MSG_DT_SUNW_CAPINFO_NF,
		MSG_DT_SUNW_STRPAD_NF,		MSG_DT_SUNW_CAPCHAIN_NF,
		MSG_DT_SUNW_LDMACH_NF,		0,
		MSG_DT_SUNW_CAPCHAINENT_NF,	0,
		MSG_DT_SUNW_CAPCHAINSZ_NF,	0,
		0,				0,
		MSG_DT_SUNW_ASLR_NF
	};
	static const conv_ds_msg_t ds_sunw_auxiliary_cf = {
	    CONV_DS_MSG_INIT(DT_SUNW_AUXILIARY, tags_sunw_auxiliary_cf) };
	static const conv_ds_msg_t ds_sunw_auxiliary_cfnp = {
	    CONV_DS_MSG_INIT(DT_SUNW_AUXILIARY, tags_sunw_auxiliary_cfnp) };
	static const conv_ds_msg_t ds_sunw_auxiliary_nf = {
	    CONV_DS_MSG_INIT(DT_SUNW_AUXILIARY, tags_sunw_auxiliary_nf) };

	/*
	 * GNU: (In DT_VALRNGLO section) DT_GNU_PRELINKED - DT_GNU_LIBLISTSZ
	 */
	static const Msg	tags_gnu_prelinked_cf[] = {
		MSG_DT_GNU_PRELINKED_CF,	MSG_DT_GNU_CONFLICTSZ_CF,
		MSG_DT_GNU_LIBLISTSZ_CF
	};
	static const Msg	tags_gnu_prelinked_cfnp[] = {
		MSG_DT_GNU_PRELINKED_CFNP,	MSG_DT_GNU_CONFLICTSZ_CFNP,
		MSG_DT_GNU_LIBLISTSZ_CFNP
	};
	static const Msg	tags_gnu_prelinked_nf[] = {
		MSG_DT_GNU_PRELINKED_NF,	MSG_DT_GNU_CONFLICTSZ_NF,
		MSG_DT_GNU_LIBLISTSZ_NF
	};
	static const conv_ds_msg_t ds_gnu_prelinked_cf = {
	    CONV_DS_MSG_INIT(DT_GNU_PRELINKED, tags_gnu_prelinked_cf) };
	static const conv_ds_msg_t ds_gnu_prelinked_cfnp = {
	    CONV_DS_MSG_INIT(DT_GNU_PRELINKED, tags_gnu_prelinked_cfnp) };
	static const conv_ds_msg_t ds_gnu_prelinked_nf = {
	    CONV_DS_MSG_INIT(DT_GNU_PRELINKED, tags_gnu_prelinked_nf) };

	/*
	 * SUNW: DT_VALRNGLO - DT_VALRNGHI range.
	 */
	static const Msg	tags_checksum_cf[] = {
		MSG_DT_CHECKSUM_CF,		MSG_DT_PLTPADSZ_CF,
		MSG_DT_MOVEENT_CF,		MSG_DT_MOVESZ_CF,
		MSG_DT_FEATURE_1_CF,		MSG_DT_POSFLAG_1_CF,
		MSG_DT_SYMINSZ_CF,		MSG_DT_SYMINENT_CF
	};
	static const Msg	tags_checksum_cfnp[] = {
		MSG_DT_CHECKSUM_CFNP,		MSG_DT_PLTPADSZ_CFNP,
		MSG_DT_MOVEENT_CFNP,		MSG_DT_MOVESZ_CFNP,
		MSG_DT_FEATURE_1_CFNP,		MSG_DT_POSFLAG_1_CFNP,
		MSG_DT_SYMINSZ_CFNP,		MSG_DT_SYMINENT_CFNP
	};
	static const Msg	tags_checksum_nf[] = {
		MSG_DT_CHECKSUM_NF,		MSG_DT_PLTPADSZ_NF,
		MSG_DT_MOVEENT_NF,		MSG_DT_MOVESZ_NF,
		MSG_DT_FEATURE_1_NF,		MSG_DT_POSFLAG_1_NF,
		MSG_DT_SYMINSZ_NF,		MSG_DT_SYMINENT_NF
	};
	static const conv_ds_msg_t ds_checksum_cf = {
	    CONV_DS_MSG_INIT(DT_CHECKSUM, tags_checksum_cf) };
	static const conv_ds_msg_t ds_checksum_cfnp = {
	    CONV_DS_MSG_INIT(DT_CHECKSUM, tags_checksum_cfnp) };
	static const conv_ds_msg_t ds_checksum_nf = {
	    CONV_DS_MSG_INIT(DT_CHECKSUM, tags_checksum_nf) };

	/*
	 * GNU: (In DT_ADDRRNGLO section) DT_GNU_HASH - DT_GNU_LIBLIST
	 */
	static const Msg	tags_gnu_hash_cf[] = {
		MSG_DT_GNU_HASH_CF,		MSG_DT_TLSDESC_PLT_CF,
		MSG_DT_TLSDESC_GOT_CF,		MSG_DT_GNU_CONFLICT_CF,
		MSG_DT_GNU_LIBLIST_CF
	};
	static const Msg	tags_gnu_hash_cfnp[] = {
		MSG_DT_GNU_HASH_CFNP,		MSG_DT_TLSDESC_PLT_CFNP,
		MSG_DT_TLSDESC_GOT_CFNP,	MSG_DT_GNU_CONFLICT_CFNP,
		MSG_DT_GNU_LIBLIST_CFNP
	};
	static const Msg	tags_gnu_hash_nf[] = {
		MSG_DT_GNU_HASH_NF,		MSG_DT_TLSDESC_PLT_NF,
		MSG_DT_TLSDESC_GOT_NF,		MSG_DT_GNU_CONFLICT_NF,
		MSG_DT_GNU_LIBLIST_NF
	};
	static const conv_ds_msg_t ds_gnu_hash_cf = {
	    CONV_DS_MSG_INIT(DT_GNU_HASH, tags_gnu_hash_cf) };
	static const conv_ds_msg_t ds_gnu_hash_cfnp = {
	    CONV_DS_MSG_INIT(DT_GNU_HASH, tags_gnu_hash_cfnp) };
	static const conv_ds_msg_t ds_gnu_hash_nf = {
	    CONV_DS_MSG_INIT(DT_GNU_HASH, tags_gnu_hash_nf) };

	/*
	 * SUNW: DT_ADDRRNGLO - DT_ADDRRNGHI range.
	 */
	static const Msg	tags_config_cf[] = {
		MSG_DT_CONFIG_CF,		MSG_DT_DEPAUDIT_CF,
		MSG_DT_AUDIT_CF,		MSG_DT_PLTPAD_CF,
		MSG_DT_MOVETAB_CF,		MSG_DT_SYMINFO_CF
	};
	static const Msg	tags_config_cfnp[] = {
		MSG_DT_CONFIG_CFNP,		MSG_DT_DEPAUDIT_CFNP,
		MSG_DT_AUDIT_CFNP,		MSG_DT_PLTPAD_CFNP,
		MSG_DT_MOVETAB_CFNP,		MSG_DT_SYMINFO_CFNP
	};
	static const Msg	tags_config_nf[] = {
		MSG_DT_CONFIG_NF,		MSG_DT_DEPAUDIT_NF,
		MSG_DT_AUDIT_NF,		MSG_DT_PLTPAD_NF,
		MSG_DT_MOVETAB_NF,		MSG_DT_SYMINFO_NF
	};
	static const conv_ds_msg_t ds_config_cf = {
	    CONV_DS_MSG_INIT(DT_CONFIG, tags_config_cf) };
	static const conv_ds_msg_t ds_config_cfnp = {
	    CONV_DS_MSG_INIT(DT_CONFIG, tags_config_cfnp) };
	static const conv_ds_msg_t ds_config_nf = {
	    CONV_DS_MSG_INIT(DT_CONFIG, tags_config_nf) };

	/*
	 * SUNW: generic range. Note hole between DT_VERSYM and DT_RELACOUNT.
	 */
	static const Msg	tags_versym_cf[] = { MSG_DT_VERSYM_CF };
	static const Msg	tags_versym_cfnp[] = { MSG_DT_VERSYM_CFNP };
	static const Msg	tags_versym_nf[] = { MSG_DT_VERSYM_NF };
	static const conv_ds_msg_t ds_versym_cf = {
	    CONV_DS_MSG_INIT(DT_VERSYM, tags_versym_cf) };
	static const conv_ds_msg_t ds_versym_cfnp = {
	    CONV_DS_MSG_INIT(DT_VERSYM, tags_versym_cfnp) };
	static const conv_ds_msg_t ds_versym_nf = {
	    CONV_DS_MSG_INIT(DT_VERSYM, tags_versym_nf) };

	static const Msg	tags_relacount_cf[] = {
		MSG_DT_RELACOUNT_CF,		MSG_DT_RELCOUNT_CF,
		MSG_DT_FLAGS_1_CF,		MSG_DT_VERDEF_CF,
		MSG_DT_VERDEFNUM_CF,		MSG_DT_VERNEED_CF,
		MSG_DT_VERNEEDNUM_CF
	};
	static const Msg	tags_relacount_cfnp[] = {
		MSG_DT_RELACOUNT_CFNP,		MSG_DT_RELCOUNT_CFNP,
		MSG_DT_FLAGS_1_CFNP,		MSG_DT_VERDEF_CFNP,
		MSG_DT_VERDEFNUM_CFNP,		MSG_DT_VERNEED_CFNP,
		MSG_DT_VERNEEDNUM_CFNP
	};
	static const Msg	tags_relacount_nf[] = {
		MSG_DT_RELACOUNT_NF,		MSG_DT_RELCOUNT_NF,
		MSG_DT_FLAGS_1_NF,		MSG_DT_VERDEF_NF,
		MSG_DT_VERDEFNUM_NF,		MSG_DT_VERNEED_NF,
		MSG_DT_VERNEEDNUM_NF
	};
	static const conv_ds_msg_t ds_relacount_cf = {
	    CONV_DS_MSG_INIT(DT_RELACOUNT, tags_relacount_cf) };
	static const conv_ds_msg_t ds_relacount_cfnp = {
	    CONV_DS_MSG_INIT(DT_RELACOUNT, tags_relacount_cfnp) };
	static const conv_ds_msg_t ds_relacount_nf = {
	    CONV_DS_MSG_INIT(DT_RELACOUNT, tags_relacount_nf) };

	/*
	 * DT_LOPROC - DT_HIPROC range: solaris/sparc-only
	 */
	static const Msg tags_sparc_reg_cf[] = { MSG_DT_SPARC_REGISTER_CF };
	static const Msg tags_sparc_reg_cfnp[] = { MSG_DT_SPARC_REGISTER_CFNP };
	static const Msg tags_sparc_reg_nf[] = { MSG_DT_SPARC_REGISTER_NF };
	static const Msg tags_sparc_reg_dmp[] = { MSG_DT_SPARC_REGISTER_DMP };
	static const conv_ds_msg_t ds_sparc_reg_cf = {
	    CONV_DS_MSG_INIT(DT_SPARC_REGISTER, tags_sparc_reg_cf) };
	static const conv_ds_msg_t ds_sparc_reg_cfnp = {
	    CONV_DS_MSG_INIT(DT_SPARC_REGISTER, tags_sparc_reg_cfnp) };
	static const conv_ds_msg_t ds_sparc_reg_nf = {
	    CONV_DS_MSG_INIT(DT_SPARC_REGISTER, tags_sparc_reg_nf) };
	static const conv_ds_msg_t ds_sparc_reg_dmp = {
	    CONV_DS_MSG_INIT(DT_SPARC_REGISTER, tags_sparc_reg_dmp) };

	/*
	 * DT_LOPROC - DT_HIPROC range: Solaris osabi, all hardware
	 */
	static const Msg	tags_auxiliary_cf[] = {
		MSG_DT_AUXILIARY_CF,	MSG_DT_USED_CF,
		MSG_DT_FILTER_CF
	};
	static const Msg	tags_auxiliary_cfnp[] = {
		MSG_DT_AUXILIARY_CFNP,	MSG_DT_USED_CFNP,
		MSG_DT_FILTER_CFNP
	};
	static const Msg	tags_auxiliary_nf[] = {
		MSG_DT_AUXILIARY_NF,	MSG_DT_USED_NF,
		MSG_DT_FILTER_NF
	};
	static const conv_ds_msg_t ds_auxiliary_cf = {
	    CONV_DS_MSG_INIT(DT_AUXILIARY, tags_auxiliary_cf) };
	static const conv_ds_msg_t ds_auxiliary_cfnp = {
	    CONV_DS_MSG_INIT(DT_AUXILIARY, tags_auxiliary_cfnp) };
	static const conv_ds_msg_t ds_auxiliary_nf = {
	    CONV_DS_MSG_INIT(DT_AUXILIARY, tags_auxiliary_nf) };


	static const conv_ds_t	*retarr[MAX_RET];

	int	ndx = 0;
	int	fmt_osabi = CONV_TYPE_FMT_ALT(fmt_flags);
	int	mach_sparc, osabi_solaris, osabi_linux;



	osabi_solaris = (osabi == ELFOSABI_NONE) ||
	    (osabi == ELFOSABI_SOLARIS) || (osabi == CONV_OSABI_ALL);
	osabi_linux = (osabi == ELFOSABI_LINUX) || (osabi == CONV_OSABI_ALL);
	mach_sparc = (mach == EM_SPARC) || (mach == EM_SPARCV9) ||
	    (mach == EM_SPARC32PLUS) || (mach == CONV_MACH_ALL);

	/*
	 * Fill in retarr with the descriptors for the messages that
	 * apply to the current osabi. Note that we order these items such
	 * that the more common are placed at the beginning, and the less
	 * likely at the end. This should speed the common case.
	 *
	 * Note that the CFNP and DMP styles are very similar, so they
	 * are combined in 'default', and fmt_osabi is consulted when there
	 * are differences.
	 */
	switch (fmt_osabi) {
	case CONV_FMT_ALT_CF:
		retarr[ndx++] = CONV_DS_ADDR(ds_null_cf);
		if (osabi_solaris)
			retarr[ndx++] = CONV_DS_ADDR(ds_sunw_auxiliary_cf);
		retarr[ndx++] = CONV_DS_ADDR(ds_checksum_cf);
		retarr[ndx++] = CONV_DS_ADDR(ds_config_cf);
		retarr[ndx++] = CONV_DS_ADDR(ds_versym_cf);
		retarr[ndx++] = CONV_DS_ADDR(ds_relacount_cf);
		if (osabi_solaris) {
			retarr[ndx++] = CONV_DS_ADDR(ds_auxiliary_cf);
			if (mach_sparc) {
				retarr[ndx++] = CONV_DS_ADDR(ds_sparc_reg_cf);
				retarr[ndx++] = CONV_DS_ADDR(ds_sdreg_cf);
			}
		}
		if (osabi_linux) {
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_prelinked_cf);
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_hash_cf);
		}
		break;

	case CONV_FMT_ALT_NF:
		retarr[ndx++] = CONV_DS_ADDR(ds_null_nf);
		if (osabi_solaris)
			retarr[ndx++] = CONV_DS_ADDR(ds_sunw_auxiliary_nf);
		retarr[ndx++] = CONV_DS_ADDR(ds_checksum_nf);
		retarr[ndx++] = CONV_DS_ADDR(ds_config_nf);
		retarr[ndx++] = CONV_DS_ADDR(ds_versym_nf);
		retarr[ndx++] = CONV_DS_ADDR(ds_relacount_nf);
		if (osabi_solaris) {
			retarr[ndx++] = CONV_DS_ADDR(ds_auxiliary_nf);
			if (mach_sparc) {
				retarr[ndx++] = CONV_DS_ADDR(ds_sparc_reg_nf);
				retarr[ndx++] = CONV_DS_ADDR(ds_sdreg_nf);
			}
		}
		if (osabi_linux) {
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_prelinked_nf);
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_hash_nf);
		}
		break;
	default:
		/*
		 * The default style for the generic range is CFNP,
		 * while dump has a couple of different strings.
		 */

		retarr[ndx++] = (fmt_osabi == CONV_FMT_ALT_DUMP) ?
		    CONV_DS_ADDR(ds_null_dmp) : CONV_DS_ADDR(ds_null_cfnp);
		if (osabi_solaris)
			retarr[ndx++] = CONV_DS_ADDR(ds_sunw_auxiliary_cfnp);
		retarr[ndx++] = CONV_DS_ADDR(ds_checksum_cfnp);
		retarr[ndx++] = CONV_DS_ADDR(ds_config_cfnp);
		retarr[ndx++] = CONV_DS_ADDR(ds_versym_cfnp);
		retarr[ndx++] = CONV_DS_ADDR(ds_relacount_cfnp);
		if (osabi_solaris) {
			retarr[ndx++] = CONV_DS_ADDR(ds_auxiliary_cfnp);
			if (mach_sparc) {
				/*
				 * The default style for DT_SPARC_REGISTER
				 * is the dump style, which omits the 'SPARC_'.
				 * CFNP keeps the prefix.
				 */
				retarr[ndx++] =
				    (fmt_osabi == CONV_FMT_ALT_CFNP) ?
				    CONV_DS_ADDR(ds_sparc_reg_cfnp) :
				    CONV_DS_ADDR(ds_sparc_reg_dmp);
				retarr[ndx++] = CONV_DS_ADDR(ds_sdreg_cfnp);
			}
		}
		if (osabi_linux) {
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_prelinked_cfnp);
			retarr[ndx++] = CONV_DS_ADDR(ds_gnu_hash_cfnp);
		}
		break;
	}

	retarr[ndx++] = NULL;
	assert(ndx <= MAX_RET);
	return (retarr);
}

conv_iter_ret_t
conv_iter_dyn_tag(conv_iter_osabi_t osabi, Half mach,
    Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(osabi, mach,
	    conv_dyn_tag_strings(osabi, mach, fmt_flags), func, uvalue));
}


#define	BINDTSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE +			\
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
	static const Val_desc vda[] = {
		{ BND_NEEDED,		MSG_BND_NEEDED },
		{ BND_REFER,		MSG_BND_REFER },
		{ BND_FILTER,		MSG_BND_FILTER },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (bnd_type_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_STR_EMPTY));

	conv_arg.buf = bnd_type_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, 0);

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
	static const Val_desc vda[] = {
		{ LML_FLG_OBJADDED,	MSG_BND_ADDED },
		{ LML_FLG_OBJREEVAL,	MSG_BND_REEVAL },
		{ LML_FLG_OBJDELETED,	MSG_BND_DELETED },
		{ LML_FLG_ATEXIT,	MSG_BND_ATEXIT },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (bnd_obj_buf->buf) };

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
	(void) conv_expn_field(&conv_arg, vda, 0);

	return ((const char *)bnd_obj_buf->buf);
}
