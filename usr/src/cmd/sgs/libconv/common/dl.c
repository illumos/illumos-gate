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

#include	<string.h>
#include	"_conv.h"
#include	"dl_msg.h"

#define	MODESZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_RTLD_LAZY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_GLOBAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_NOLOAD_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_PARENT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_GROUP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_WORLD_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_NODELETE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_FIRST_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_RTLD_CONFGEN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE


/*
 * Ensure that Conv_dl_mode_buf_t is large enough:
 *
 * MODESZ is the real minimum size of the buffer required by conv_dl_mode().
 * However, Conv_dl_mode_buf_t uses CONV_DL_MODE_BUFSIZE to set the
 * buffer size. We do things this way because the definition of MODESZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DL_MODE_BUFSIZE != MODESZ) && !defined(__lint)
#define	REPORT_BUFSIZE MODESZ
#include "report_bufsize.h"
#error "CONV_DL_MODE_BUFSIZE does not match MODESZ"
#endif

/*
 * String conversion routine for dlopen() attributes.
 */
const char *
conv_dl_mode(int mode, int fabricate, Conv_dl_mode_buf_t *dl_mode_buf)
{
	static Val_desc vda[] = {
		{ RTLD_NOLOAD,		MSG_ORIG(MSG_RTLD_NOLOAD) },
		{ RTLD_PARENT,		MSG_ORIG(MSG_RTLD_PARENT) },
		{ RTLD_GROUP,		MSG_ORIG(MSG_RTLD_GROUP) },
		{ RTLD_WORLD,		MSG_ORIG(MSG_RTLD_WORLD) },
		{ RTLD_NODELETE,	MSG_ORIG(MSG_RTLD_NODELETE) },
		{ RTLD_FIRST,		MSG_ORIG(MSG_RTLD_FIRST) },
		{ RTLD_CONFGEN,		MSG_ORIG(MSG_RTLD_CONFGEN) },
		{ 0,			0 }
	};
	static const char *leading_str_arr[3];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dl_mode_buf->buf), vda, leading_str_arr };

	const char **lstr = leading_str_arr;

	conv_arg.buf = dl_mode_buf->buf;
	conv_arg.oflags = conv_arg.rflags = mode;


	if (mode & RTLD_NOW) {
		*lstr++ = MSG_ORIG(MSG_RTLD_NOW);
	} else if ((mode & RTLD_LAZY) || fabricate) {
		*lstr++ = MSG_ORIG(MSG_RTLD_LAZY);
	}
	if (mode & RTLD_GLOBAL) {
		*lstr++ = MSG_ORIG(MSG_RTLD_GLOBAL);
	} else if (fabricate) {
		*lstr++ = MSG_ORIG(MSG_RTLD_LOCAL);
	}
	*lstr = NULL;
	conv_arg.oflags = mode;
	conv_arg.rflags = mode & ~(RTLD_LAZY | RTLD_NOW | RTLD_GLOBAL);

	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)dl_mode_buf->buf);
}

/*
 * Note: We can use two different sets of prefix/separator/suffix
 * strings in conv_dl_flag(), depending on the value of the separator
 * argument. To size the buffer, I use the default prefix and suffix
 * sizes, and the alternate separator size, because they are larger.
 */

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_RTLD_REL_RELATIVE_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_EXEC_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_DEPENDS_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_PRELOAD_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_SELF_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_REL_WEAK_SIZE +	MSG_GBL_SEP_SIZE + \
		MSG_RTLD_MEMORY_SIZE +		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_STRIP_SIZE +		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_NOHEAP_SIZE +		MSG_GBL_SEP_SIZE + \
		MSG_RTLD_CONFSET_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_dl_flag_buf_t is large enough:
 *
 * FLAGSZ is the real minimum size of the buffer required by conv_dl_flag().
 * However, Conv_dl_flag_buf_t uses CONV_DL_FLAG_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FLAGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DL_FLAG_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_DL_FLAG_BUFSIZE does not match FLAGSZ"
#endif

/*
 * String conversion routine for dldump() flags.
 * crle(1) uses this routine to generate update information, and in this case
 * we build a "|" separated string.
 */
const char *
conv_dl_flag(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_dl_flag_buf_t *dl_flag_buf)
{
	static Val_desc vda[] = {
		{ RTLD_REL_RELATIVE,	MSG_ORIG(MSG_RTLD_REL_RELATIVE) },
		{ RTLD_REL_EXEC,	MSG_ORIG(MSG_RTLD_REL_EXEC) },
		{ RTLD_REL_DEPENDS,	MSG_ORIG(MSG_RTLD_REL_DEPENDS) },
		{ RTLD_REL_PRELOAD,	MSG_ORIG(MSG_RTLD_REL_PRELOAD) },
		{ RTLD_REL_SELF,	MSG_ORIG(MSG_RTLD_REL_SELF) },
		{ RTLD_REL_WEAK,	MSG_ORIG(MSG_RTLD_REL_WEAK) },
		{ RTLD_MEMORY,		MSG_ORIG(MSG_RTLD_MEMORY) },
		{ RTLD_STRIP,		MSG_ORIG(MSG_RTLD_STRIP) },
		{ RTLD_NOHEAP,		MSG_ORIG(MSG_RTLD_NOHEAP) },
		{ RTLD_CONFSET,		MSG_ORIG(MSG_RTLD_CONFSET) },
		{ 0,			0 }
	};
	static const char *leading_str_arr[2];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dl_flag_buf->buf), vda, leading_str_arr };

	const char **lstr = leading_str_arr;

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = dl_flag_buf->buf;
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_CRLE) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_GBL_QUOTE);
		conv_arg.sep = MSG_ORIG(MSG_GBL_SEP);
	} else {		/* Use default delimiters */
		conv_arg.prefix = conv_arg.suffix = conv_arg.sep = NULL;
	}

	if ((flags & RTLD_REL_ALL) == RTLD_REL_ALL) {
		*lstr++ = MSG_ORIG(MSG_RTLD_REL_ALL);
		flags &= ~RTLD_REL_ALL;
	}
	*lstr = NULL;
	conv_arg.oflags = conv_arg.rflags = flags;

	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)dl_flag_buf->buf);
}
