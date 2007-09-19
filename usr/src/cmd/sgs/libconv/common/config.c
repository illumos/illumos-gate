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

#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	"rtc.h"
#include	"_conv.h"
#include	"config_msg.h"

#define	FEATSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_CONF_EDLIBPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ESLIBPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ADLIBPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ASLIBPATH_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_DIRCFG_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_OBJALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_MEMRESV_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ENVS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_FLTR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_config_feat_buf_t is large enough:
 *
 * FEATSZ is the real minimum size of the buffer required by conv_config_feat().
 * However, Conv_config_feat_buf_t uses CONV_CONFIG_FEAT_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FEATSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CONFIG_FEAT_BUFSIZE < FEATSZ) && !defined(__lint)
#error "CONV_CONFIG_FEAT_BUFSIZE is not large enough"
#endif

/*
 * String conversion routine for configuration file information.
 */
const char *
conv_config_feat(int features, Conv_config_feat_buf_t *config_feat_buf)
{
	static Val_desc	vda[] = {
		{ CONF_EDLIBPATH,	MSG_ORIG(MSG_CONF_EDLIBPATH) },
		{ CONF_ESLIBPATH,	MSG_ORIG(MSG_CONF_ESLIBPATH) },
		{ CONF_ADLIBPATH,	MSG_ORIG(MSG_CONF_ADLIBPATH) },
		{ CONF_ASLIBPATH,	MSG_ORIG(MSG_CONF_ASLIBPATH) },
		{ CONF_DIRCFG,		MSG_ORIG(MSG_CONF_DIRCFG) },
		{ CONF_OBJALT,		MSG_ORIG(MSG_CONF_OBJALT) },
		{ CONF_MEMRESV,		MSG_ORIG(MSG_CONF_MEMRESV) },
		{ CONF_ENVS,		MSG_ORIG(MSG_CONF_ENVS) },
		{ CONF_FLTR,		MSG_ORIG(MSG_CONF_FLTR) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (config_feat_buf->buf), vda };

	conv_arg.buf = config_feat_buf->buf;
	conv_arg.oflags = conv_arg.rflags = features;
	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)config_feat_buf->buf);
}

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_CONF_DIRENT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ALLENTS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_NOEXIST_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_EXEC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_ALTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_OPTIONAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_DUMP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_REALPATH_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_NOALTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_GROUP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_APP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_CMDLINE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_FILTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_CONF_FILTEE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_config_obj_buf_t is large enough:
 *
 * FLAGSZ is the real minimum size of the buffer required by conv_config_obj().
 * However, Conv_config_obj_buf_t uses CONV_CONFIG_OBJ_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FLAGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CONFIG_OBJ_BUFSIZE < FLAGSZ) && !defined(__lint)
#error "CONV_CONFIG_OBJ_BUFSIZE is not large enough"
#endif

/*
 * String conversion routine for object flags.
 */
const char *
conv_config_obj(ushort_t flags, Conv_config_obj_buf_t *config_obj_buf)
{
	static Val_desc vda[] = {
		{ RTC_OBJ_DIRENT,	MSG_ORIG(MSG_CONF_DIRENT) },
		{ RTC_OBJ_ALLENTS,	MSG_ORIG(MSG_CONF_ALLENTS) },
		{ RTC_OBJ_NOEXIST,	MSG_ORIG(MSG_CONF_NOEXIST) },
		{ RTC_OBJ_EXEC,		MSG_ORIG(MSG_CONF_EXEC) },
		{ RTC_OBJ_ALTER,	MSG_ORIG(MSG_CONF_ALTER) },
		{ RTC_OBJ_DUMP,		MSG_ORIG(MSG_CONF_DUMP) },
		{ RTC_OBJ_NOALTER,	MSG_ORIG(MSG_CONF_NOALTER) },
		{ RTC_OBJ_REALPTH,	MSG_ORIG(MSG_CONF_REALPATH) },
		{ RTC_OBJ_GROUP,	MSG_ORIG(MSG_CONF_GROUP) },
		{ RTC_OBJ_APP,		MSG_ORIG(MSG_CONF_APP) },
		{ RTC_OBJ_CMDLINE,	MSG_ORIG(MSG_CONF_CMDLINE) },
		{ RTC_OBJ_FILTER,	MSG_ORIG(MSG_CONF_FILTER) },
		{ RTC_OBJ_FILTEE,	MSG_ORIG(MSG_CONF_FILTEE) },
		{ 0,			0 }
	};
	static const char *leading_str_arr[2];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (config_obj_buf->buf), vda, leading_str_arr };

	const char **lstr = leading_str_arr;

	if ((flags == 0) || (flags == RTC_OBJ_OPTINAL))
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = config_obj_buf->buf;
	conv_arg.rflags = flags;

	/*
	 * Print an alternative-optional object simply as optional.
	 */
	if ((flags & (RTC_OBJ_ALTER | RTC_OBJ_OPTINAL)) ==
	    (RTC_OBJ_ALTER | RTC_OBJ_OPTINAL)) {
		*lstr++ = MSG_ORIG(MSG_CONF_OPTIONAL);
		conv_arg.rflags &= ~(RTC_OBJ_ALTER | RTC_OBJ_OPTINAL);
	}
	*lstr = NULL;
	conv_arg.oflags = conv_arg.rflags &= ~RTC_OBJ_OPTINAL;

	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)config_obj_buf->buf);
}

/*
 * Determine whether and old pathname exists within a search path string,
 * without a new pathname, i.e., does the search path string contain "/usr/lib"
 * but not "/lib".  If so, add the new pathname before the old pathname.  For
 * example, convert:
 *
 *	/local/lib:/opt/sfw/lib:/usr/lib
 * to:
 *	/local/lib:/opt/sfw/lib:/lib:/usr/lib
 */
const char *
conv_config_upm(const char *str, const char *old, const char *new,
    size_t newlen)
{
	const char	*curstr, *ptr;
	const char	*curold = 0, *curnew = 0;
	const char	*ptrold = old, * ptrnew = new;
	int		chkold = 1, chknew = 1;

	for (curstr = ptr = str; *ptr; ptr++) {
		if (*ptr == ':') {
			/*
			 * We've come to the end of a token within the string.
			 */
			if ((uintptr_t)ptr - (uintptr_t)curstr) {
				/*
				 * If the old or new string checking is still
				 * enabled, we've found a match.
				 */
				if (chkold)
					curold = curstr;
				if (chknew)
					curnew = curstr;
			}
			curstr = (char *)(ptr + 1);

			/*
			 * If an old or new string hasn't yet been matched,
			 * re-enable the checking for either.
			 */
			if (curold == 0) {
				ptrold = old;
				chkold = 1;
			}
			if (curnew == 0) {
				ptrnew = new;
				chknew = 1;
			}
			continue;
		}

		/*
		 * Determine if the current token matches the old or new string.
		 * If not, disable the checking for each string.
		 */
		if (chkold && (*ptr != *ptrold++))
			chkold = 0;
		if (chknew && (*ptr != *ptrnew++))
			chknew = 0;
	}

	/*
	 * We've come to the end of the string, if the old or new string
	 * checking is still enabled, we've found a match.
	 */
	if ((uintptr_t)ptr - (uintptr_t)curstr) {
		if (chkold)
			curold = curstr;
		if (chknew)
			curnew = curstr;
	}

	/*
	 * If an old string hasn't been found, or it has and a new string has
	 * been found, return the original string.
	 */
	if ((curold == 0) || curnew)
		return (str);
	else {
		char	*newstr;
		size_t	len;

		/*
		 * Allocate a new string, enlarged to accommodate the new string
		 * that will be inserted, and an associated separator.
		 */
		if ((curstr = malloc(newlen + 2 +
		    (uintptr_t)ptr - (uintptr_t)str)) == 0)
			return (str);

		newstr = (char *)curstr;
		for (len = (uintptr_t)curold - (uintptr_t)str; len; len--)
			*(newstr++) = *(str++);		/* copy up to */
							/*    insertion point */
		for (len = newlen; len; len--)
			*(newstr++) = *(new++);		/* add new string and */
		*(newstr++) = ':';			/*    separator */
		for (len = (uintptr_t)ptr - (uintptr_t)str; len; len--)
			*(newstr++) = *(str++);		/* add remaining */
		*(newstr++) = '\0';			/*	string */

		return (curstr);
	}
}
