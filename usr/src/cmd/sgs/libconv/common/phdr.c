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
 * String conversion routines for program header attributes.
 */
#include	<string.h>
#include	<_conv.h>
#include	<phdr_msg.h>

static const Msg uphdrs[] = {
	MSG_PT_SUNWBSS,		MSG_PT_SUNWSTACK,	MSG_PT_SUNWDTRACE,
	MSG_PT_SUNWCAP
};

const char *
conv_phdr_type(Half mach, Word type)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	phdrs[] = {
		MSG_PT_NULL,		MSG_PT_LOAD,		MSG_PT_DYNAMIC,
		MSG_PT_INTERP,		MSG_PT_NOTE,		MSG_PT_SHLIB,
		MSG_PT_PHDR,		MSG_PT_TLS
	};

	if (type < PT_NUM)
		return (MSG_ORIG(phdrs[type]));
	else if ((type >= PT_SUNWBSS) && (type <= PT_HISUNW))
		return (MSG_ORIG(uphdrs[type - PT_SUNWBSS]));
	else if ((type == PT_SUNW_UNWIND) && (mach == EM_AMD64))
		return (MSG_ORIG(MSG_PT_SUNW_UNWIND));
	else
		return (conv_invalid_val(string, CONV_INV_STRSIZE, type, 0));
}

#define	PHDRSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_PF_X_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_W_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_R_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_SUNW_FAILURE_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_phdr_flags(Word flags)
{
	static char string[PHDRSZ];
	static Val_desc vda[] = {
		{ PF_X,			MSG_ORIG(MSG_PF_X) },
		{ PF_W,			MSG_ORIG(MSG_PF_W) },
		{ PF_R,			MSG_ORIG(MSG_PF_R) },
		{ PF_SUNW_FAILURE,	MSG_ORIG(MSG_PF_SUNW_FAILURE) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}
