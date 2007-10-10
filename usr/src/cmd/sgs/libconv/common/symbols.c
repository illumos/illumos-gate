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
 * String conversion routines for symbol attributes.
 */
#include	<stdio.h>
#include	<sys/machelf.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	"_conv.h"
#include	"symbols_msg.h"

const char *
conv_sym_other(uchar_t other, Conv_inv_buf_t *inv_buf)
{
	static const char	visibility[7] = {
		'D',	/* STV_DEFAULT */
		'I',	/* STV_INTERNAL */
		'H',	/* STV_HIDDEN */
		'P',	/* STV_PROTECTED */
		'X',	/* STV_EXPORTED */
		'S',	/* STV_SINGLETON */
		'E'	/* STV_ELIMINATE */
	};
	uchar_t		vis = ELF_ST_VISIBILITY(other);
	uint_t		ndx = 0;

	inv_buf->buf[ndx++] = visibility[vis];

	/*
	 * If unknown bits are present in st_other - throw out a '?'
	 */
	if (other & ~MSK_SYM_VISIBILITY)
		inv_buf->buf[ndx++] = '?';
	inv_buf->buf[ndx++] = '\0';

	return (inv_buf->buf);
}

const char *
conv_sym_other_vis(uchar_t value, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	vis[] = {
		MSG_STV_DEFAULT,	MSG_STV_INTERNAL,
		MSG_STV_HIDDEN,		MSG_STV_PROTECTED,
		MSG_STV_EXPORTED,	MSG_STV_SINGLETON,
		MSG_STV_ELIMINATE
	};

	static const Msg	vis_alt[] = {
		MSG_STV_DEFAULT_ALT,	MSG_STV_INTERNAL_ALT,
		MSG_STV_HIDDEN_ALT,	MSG_STV_PROTECTED_ALT,
		MSG_STV_EXPORTED_ALT,	MSG_STV_SINGLETON_ALT,
		MSG_STV_ELIMINATE_ALT
	};

	if (value >= (sizeof (vis) / sizeof (vis[0])))
		return (conv_invalid_val(inv_buf, value, fmt_flags));

	/* If full ELF names are desired, use those strings */
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_FULLNAME)
		return (MSG_ORIG(vis_alt[value]));

	/* Default strings */
	return (MSG_ORIG(vis[value]));
}

const char *
conv_sym_info_type(Half mach, uchar_t type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	types[] = {
		MSG_STT_NOTYPE,		MSG_STT_OBJECT,
		MSG_STT_FUNC,		MSG_STT_SECTION,
		MSG_STT_FILE,		MSG_STT_COMMON,
		MSG_STT_TLS
	};

	static const Msg	types_alt[] = {
		MSG_STT_NOTYPE_ALT,	MSG_STT_OBJECT_ALT,
		MSG_STT_FUNC_ALT,	MSG_STT_SECTION_ALT,
		MSG_STT_FILE_ALT,	MSG_STT_COMMON_ALT,
		MSG_STT_TLS_ALT
	};

	if (type < STT_NUM) {
		/* If full ELF names are desired, use those strings */
		if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_FULLNAME)
			return (MSG_ORIG(types_alt[type]));

		/* Default strings */
		return (MSG_ORIG(types[type]));
	} else if (((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9)) && (type == STT_SPARC_REGISTER)) {
		if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_FULLNAME)
			return (MSG_ORIG(MSG_STT_SPARC_REGISTER_ALT));

		return (MSG_ORIG(MSG_STT_SPARC_REGISTER));
	} else {
		return (conv_invalid_val(inv_buf, type, fmt_flags));
	}
}

const char *
conv_sym_info_bind(uchar_t bind, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	binds[] = {
		MSG_STB_LOCAL,		MSG_STB_GLOBAL,		MSG_STB_WEAK
	};

	static const Msg	binds_alt[] = {
		MSG_STB_LOCAL_ALT,	MSG_STB_GLOBAL_ALT,	MSG_STB_WEAK_ALT
	};

	if (bind >= STB_NUM)
		return (conv_invalid_val(inv_buf, bind, fmt_flags));

	/* If full ELF names are desired, use those strings */
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_FULLNAME)
		return (MSG_ORIG(binds_alt[bind]));

	/* Default strings */
	return (MSG_ORIG(binds[bind]));
}

const char *
conv_sym_shndx(Half shndx, Conv_inv_buf_t *inv_buf)
{
	switch (shndx) {
	case SHN_UNDEF:
		return (MSG_ORIG(MSG_SHN_UNDEF));
	case SHN_SUNW_IGNORE:
		return (MSG_ORIG(MSG_SHN_SUNW_IGNORE));
	case SHN_ABS:
		return (MSG_ORIG(MSG_SHN_ABS));
	case SHN_COMMON:
		return (MSG_ORIG(MSG_SHN_COMMON));
	case SHN_AMD64_LCOMMON:
		return (MSG_ORIG(MSG_SHN_AMD64_LCOMMON));
	case SHN_AFTER:
		return (MSG_ORIG(MSG_SHN_AFTER));
	case SHN_BEFORE:
		return (MSG_ORIG(MSG_SHN_BEFORE));
	case SHN_XINDEX:
		return (MSG_ORIG(MSG_SHN_XINDEX));
	default:
		return (conv_invalid_val(inv_buf, shndx, CONV_FMT_DECIMAL));
	}
}

const char *
conv_sym_value(Half mach, uchar_t type, Addr value, Conv_inv_buf_t *inv_buf)
{
	if (((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9)) && (type == STT_SPARC_REGISTER))
		return (conv_sym_SPARC_value(value, 0, inv_buf));

	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf),
	    MSG_ORIG(MSG_SYM_FMT_VAL), EC_ADDR(value));
	return (inv_buf->buf);
}
