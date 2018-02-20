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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * String conversion routines for syminfo attributes.
 */
#include	<stdio.h>
#include	<_machelf.h>
#include	"_conv.h"
#include	"syminfo_msg.h"



static const Val_desc *
conv_syminfo_flags_strings(Conv_fmt_flags_t fmt_flags)
{
#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_SYMINFO_FLG_DIRECT_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_FILTER_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_COPY_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_LAZYLOAD_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_DIRECTBIND_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_NOEXTDIRECT_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_AUXILIARY_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_INTERPOSE_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_CAP_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_DEFERRED_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_syminfo_flags_buf_t is large enough:
	 *
	 * FLAGSZ is the real minimum size of the buffer required by
	 * conv_syminfo_flags(). However, Conv_syminfo_flags_buf_t uses
	 * CONV_SYMINFO_FLAGS_BUFSIZE to set the buffer size. We do things
	 * this way because the definition of FLAGSZ uses information that
	 * is not available in the environment of other programs that include
	 * the conv.h header file.
	 */
#if (CONV_SYMINFO_FLAGS_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_SYMINFO_FLAGS_BUFSIZE does not match FLAGSZ"
#endif

	static const Val_desc vda_cf[] = {
		{ SYMINFO_FLG_DIRECT,	MSG_SYMINFO_FLG_DIRECT_CF },
		{ SYMINFO_FLG_FILTER,	MSG_SYMINFO_FLG_FILTER_CF },
		{ SYMINFO_FLG_COPY,	MSG_SYMINFO_FLG_COPY_CF },
		{ SYMINFO_FLG_LAZYLOAD,	MSG_SYMINFO_FLG_LAZYLOAD_CF },
		{ SYMINFO_FLG_DIRECTBIND, MSG_SYMINFO_FLG_DIRECTBIND_CF },
		{ SYMINFO_FLG_NOEXTDIRECT, MSG_SYMINFO_FLG_NOEXTDIRECT_CF },
		{ SYMINFO_FLG_AUXILIARY, MSG_SYMINFO_FLG_AUXILIARY_CF },
		{ SYMINFO_FLG_INTERPOSE, MSG_SYMINFO_FLG_INTERPOSE_CF },
		{ SYMINFO_FLG_CAP,	MSG_SYMINFO_FLG_CAP_CF },
		{ SYMINFO_FLG_DEFERRED,	MSG_SYMINFO_FLG_DEFERRED_CF },
		{ 0 }
	};
	static const Val_desc vda_cfnp[] = {
		{ SYMINFO_FLG_DIRECT,	MSG_SYMINFO_FLG_DIRECT_CFNP },
		{ SYMINFO_FLG_FILTER,	MSG_SYMINFO_FLG_FILTER_CFNP },
		{ SYMINFO_FLG_COPY,	MSG_SYMINFO_FLG_COPY_CFNP },
		{ SYMINFO_FLG_LAZYLOAD,	MSG_SYMINFO_FLG_LAZYLOAD_CFNP },
		{ SYMINFO_FLG_DIRECTBIND, MSG_SYMINFO_FLG_DIRECTBIND_CFNP },
		{ SYMINFO_FLG_NOEXTDIRECT, MSG_SYMINFO_FLG_NOEXTDIRECT_CFNP },
		{ SYMINFO_FLG_AUXILIARY, MSG_SYMINFO_FLG_AUXILIARY_CFNP },
		{ SYMINFO_FLG_INTERPOSE, MSG_SYMINFO_FLG_INTERPOSE_CFNP },
		{ SYMINFO_FLG_CAP,	MSG_SYMINFO_FLG_CAP_CFNP },
		{ SYMINFO_FLG_DEFERRED,	MSG_SYMINFO_FLG_DEFERRED_CFNP },
		{ 0 }
	};
	static const Val_desc vda_nf[] = {
		{ SYMINFO_FLG_DIRECT,	MSG_SYMINFO_FLG_DIRECT_NF },
		{ SYMINFO_FLG_FILTER,	MSG_SYMINFO_FLG_FILTER_NF },
		{ SYMINFO_FLG_COPY,	MSG_SYMINFO_FLG_COPY_NF },
		{ SYMINFO_FLG_LAZYLOAD,	MSG_SYMINFO_FLG_LAZYLOAD_NF },
		{ SYMINFO_FLG_DIRECTBIND, MSG_SYMINFO_FLG_DIRECTBIND_NF },
		{ SYMINFO_FLG_NOEXTDIRECT, MSG_SYMINFO_FLG_NOEXTDIRECT_NF },
		{ SYMINFO_FLG_AUXILIARY, MSG_SYMINFO_FLG_AUXILIARY_NF },
		{ SYMINFO_FLG_INTERPOSE, MSG_SYMINFO_FLG_INTERPOSE_NF },
		{ SYMINFO_FLG_CAP,	MSG_SYMINFO_FLG_CAP_NF },
		{ SYMINFO_FLG_DEFERRED,	MSG_SYMINFO_FLG_DEFERRED_NF },
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


const char *
conv_syminfo_flags(Half flags, Conv_fmt_flags_t fmt_flags,
    Conv_syminfo_flags_buf_t *syminfo_flags_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (syminfo_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = syminfo_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	conv_arg.prefix = conv_arg.suffix = NULL;
	(void) conv_expn_field(&conv_arg,
	    conv_syminfo_flags_strings(fmt_flags), fmt_flags);

	return ((const char *)syminfo_flags_buf->buf);
}

conv_iter_ret_t
conv_iter_syminfo_flags(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_vd(conv_syminfo_flags_strings(fmt_flags),
	    func, uvalue));
}


static const conv_ds_t **
conv_syminfo_boundto_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	boundto_cf[] = {
		MSG_SYMINFO_BT_EXTERN_CF,	MSG_SYMINFO_BT_NONE_CF,
		MSG_SYMINFO_BT_PARENT_CF,	MSG_SYMINFO_BT_SELF_CF
	};
	static const Msg	boundto_cfnp[] = {
		MSG_SYMINFO_BT_EXTERN_CFNP,	MSG_SYMINFO_BT_NONE_CFNP,
		MSG_SYMINFO_BT_PARENT_CFNP,	MSG_SYMINFO_BT_SELF_CFNP
	};
	static const Msg	boundto_nf[] = {
		MSG_SYMINFO_BT_EXTERN_NF,	MSG_SYMINFO_BT_NONE_NF,
		MSG_SYMINFO_BT_PARENT_NF,	MSG_SYMINFO_BT_SELF_NF
	};
	static const conv_ds_msg_t ds_boundto_cf = {
	    CONV_DS_MSG_INIT(SYMINFO_BT_EXTERN, boundto_cf) };
	static const conv_ds_msg_t ds_boundto_cfnp = {
	    CONV_DS_MSG_INIT(SYMINFO_BT_EXTERN, boundto_cfnp) };
	static const conv_ds_msg_t ds_boundto_nf = {
	    CONV_DS_MSG_INIT(SYMINFO_BT_EXTERN, boundto_nf) };

	/* Build NULL terminated return arrays for each string style */
	static const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_boundto_cf), NULL };
	static const conv_ds_t	*ds_cfnp[] = {
		CONV_DS_ADDR(ds_boundto_cfnp), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_boundto_nf), NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (ds_cf);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cfnp);
}

const char *
conv_syminfo_boundto(Half value, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, value,
	    conv_syminfo_boundto_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_syminfo_boundto(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    conv_syminfo_boundto_strings(fmt_flags), func, uvalue));
}
