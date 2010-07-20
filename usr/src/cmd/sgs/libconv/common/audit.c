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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<string.h>
#include	<link.h>
#include	"_conv.h"
#include	"audit_msg.h"

#define	BINDSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_LA_FLG_BINDTO_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_FLG_BINDFROM_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_la_bind_buf_t is large enough:
 *
 * BINDSZ is the real minimum size of the buffer required by conv_la_bind().
 * However, Conv_la_bind_buf_t uses CONV_LA_BIND_BUFSIZE to set the
 * buffer size. We do things this way because the definition of BINDSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_LA_BIND_BUFSIZE != BINDSZ) && !defined(__lint)
#define	REPORT_BUFSIZE BINDSZ
#include "report_bufsize.h"
#error "CONV_LA_BIND_BUFSIZE does not match BINDSZ"
#endif

/*
 * String conversion routine for la_objopen() return flags.
 */
const char *
conv_la_bind(uint_t bind, Conv_la_bind_buf_t *la_bind_buf)
{
	static const Val_desc vda[] = {
		{ LA_FLG_BINDTO,	MSG_LA_FLG_BINDTO },
		{ LA_FLG_BINDFROM,	MSG_LA_FLG_BINDFROM },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (la_bind_buf->buf), NULL };

	if (bind == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = la_bind_buf->buf;
	conv_arg.oflags = conv_arg.rflags = bind;

	(void) conv_expn_field(&conv_arg, vda, 0);

	return ((const char *)la_bind_buf->buf);
}

#define	SEARCHSZ CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_LA_SER_ORIG_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SER_LIBPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SER_RUNPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SER_DEFAULT_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SER_CONFIG_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SER_SECURE_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_la_search_buf_t is large enough:
 *
 * SEARCHSZ is the real minimum size of the buffer required by conv_la_search().
 * However, Conv_la_search_buf_t uses CONV_LA_SEARCH_BUFSIZE to set the
 * buffer size. We do things this way because the definition of SEARCHSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_LA_SEARCH_BUFSIZE != SEARCHSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SEARCHSZ
#include "report_bufsize.h"
#error "CONV_LA_SEARCH_BUFSIZE does not match SEARCHSZ"
#endif

/*
 * String conversion routine for la_objsearch() flags.
 */
const char *
conv_la_search(uint_t search, Conv_la_search_buf_t *la_search_buf)
{
	static const Val_desc vda[] = {
		{ LA_SER_ORIG,		MSG_LA_SER_ORIG },
		{ LA_SER_LIBPATH,	MSG_LA_SER_LIBPATH },
		{ LA_SER_RUNPATH,	MSG_LA_SER_RUNPATH },
		{ LA_SER_DEFAULT,	MSG_LA_SER_DEFAULT },
		{ LA_SER_CONFIG,	MSG_LA_SER_CONFIG },
		{ LA_SER_SECURE,	MSG_LA_SER_SECURE },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (la_search_buf->buf), NULL };

	if (search == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = la_search_buf->buf;
	conv_arg.oflags = conv_arg.rflags = search;

	(void) conv_expn_field(&conv_arg, vda, 0);

	return ((const char *)la_search_buf->buf);
}

/*
 * String conversion routine for la_objopen() return flags.
 */

/*
 * String conversion routine for la_activity() flags.
 */
const char *
conv_la_activity(uint_t request, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	requests[LA_ACT_MAX] = {
		MSG_LA_ACT_CONSISTENT,	/* MSG_ORIG(MSG_LA_ACT_CONSISTENT) */
		MSG_LA_ACT_ADD,		/* MSG_ORIG(MSG_LA_ACT_ADD) */
		MSG_LA_ACT_DELETE	/* MSG_ORIG(MSG_LA_ACT_DELETE) */
	};
	static const conv_ds_msg_t ds_requests = {
	    CONV_DS_MSG_INIT(LA_ACT_CONSISTENT, requests) };

	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_requests), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, request, ds, fmt_flags,
	    inv_buf));
}

#define	SYMBSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_LA_SYMB_NOPLTENTER_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SYMB_NOPLTEXIT_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SYMB_STRUCTCALL_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SYMB_DLSYM_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_LA_SYMB_ALTVALUE_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_la_symbind_buf_t is large enough:
 *
 * SYMBSZ is the real minimum size of the buffer required by conv_la_symbind().
 * However, Conv_la_symbind_buf_t uses CONV_LA_SYMB_BUFSIZE to set the
 * buffer size. We do things this way because the definition of SYMBSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_LA_SYMBIND_BUFSIZE != SYMBSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SYMBSZ
#include "report_bufsize.h"
#error "CONV_LA_SYMBIND_BUFSIZE does not match SYMBSZ"
#endif

/*
 * String conversion routine for la_symbind() flags.
 */
const char *
conv_la_symbind(uint_t symbind, Conv_la_symbind_buf_t *la_symbind_buf)
{
	static const Val_desc vda[] = {
		{ LA_SYMB_NOPLTENTER,	MSG_LA_SYMB_NOPLTENTER },
		{ LA_SYMB_NOPLTEXIT,	MSG_LA_SYMB_NOPLTEXIT },
		{ LA_SYMB_STRUCTCALL,	MSG_LA_SYMB_STRUCTCALL },
		{ LA_SYMB_DLSYM,	MSG_LA_SYMB_DLSYM },
		{ LA_SYMB_ALTVALUE,	MSG_LA_SYMB_ALTVALUE },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (la_symbind_buf->buf), NULL };

	if (symbind == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = la_symbind_buf->buf;
	conv_arg.oflags = conv_arg.rflags = symbind;

	(void) conv_expn_field(&conv_arg, vda, 0);

	return ((const char *)la_symbind_buf->buf);
}
