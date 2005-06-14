/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<string.h>
#include	"rtc.h"
#include	"_conv.h"
#include	"config_msg.h"

#define	MODESZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_CONF_EDLIBPATH_SIZE + \
		MSG_CONF_ADLIBPATH_SIZE + \
		MSG_CONF_ESLIBPATH_SIZE + \
		MSG_CONF_ASLIBPATH_SIZE + \
		MSG_CONF_DIRCFG_SIZE + \
		MSG_CONF_OBJALT_SIZE + \
		MSG_CONF_ENVS_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for configuration file information.
 */
const char *
conv_config_str(int feature)
{
	static	char	string[MODESZ] = { '\0' };

	(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

	if (feature & CONF_EDLIBPATH)
		(void) strcat(string, MSG_ORIG(MSG_CONF_EDLIBPATH));
	if (feature & CONF_ESLIBPATH)
		(void) strcat(string, MSG_ORIG(MSG_CONF_ESLIBPATH));
	if (feature & CONF_ADLIBPATH)
		(void) strcat(string, MSG_ORIG(MSG_CONF_ADLIBPATH));
	if (feature & CONF_ASLIBPATH)
		(void) strcat(string, MSG_ORIG(MSG_CONF_ASLIBPATH));
	if (feature & CONF_DIRCFG)
		(void) strcat(string, MSG_ORIG(MSG_CONF_DIRCFG));
	if (feature & CONF_OBJALT)
		(void) strcat(string, MSG_ORIG(MSG_CONF_OBJALT));
	if (feature & CONF_MEMRESV)
		(void) strcat(string, MSG_ORIG(MSG_CONF_MEMRESV));
	if (feature & CONF_ENVS)
		(void) strcat(string, MSG_ORIG(MSG_CONF_ENVS));
	if (feature & CONF_FLTR)
		(void) strcat(string, MSG_ORIG(MSG_CONF_FLTR));

	(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

	return ((const char *)string);
}

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_CONF_DIRENT_SIZE + \
		MSG_CONF_NOEXIST_SIZE + \
		MSG_CONF_ALLENTS_SIZE + \
		MSG_CONF_EXEC_SIZE + \
		MSG_CONF_ALTER_SIZE + \
		MSG_CONF_DUMP_SIZE + \
		MSG_CONF_REALPATH_SIZE + \
		MSG_CONF_GROUP_SIZE + \
		MSG_CONF_APP_SIZE + \
		MSG_CONF_CMDLINE_SIZE + \
		MSG_CONF_FILTER_SIZE + \
		MSG_CONF_FILTEE_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for object flags.
 */
const char *
conv_config_obj(ushort_t flags)
{
	static char	string[FLAGSZ] = { '\0' };

	(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

	if (flags & RTC_OBJ_DIRENT)
		(void) strcat(string, MSG_ORIG(MSG_CONF_DIRENT));
	if (flags & RTC_OBJ_ALLENTS)
		(void) strcat(string, MSG_ORIG(MSG_CONF_ALLENTS));
	if (flags & RTC_OBJ_NOEXIST)
		(void) strcat(string, MSG_ORIG(MSG_CONF_NOEXIST));
	if (flags & RTC_OBJ_EXEC)
		(void) strcat(string, MSG_ORIG(MSG_CONF_EXEC));
	if (flags & RTC_OBJ_ALTER) {
		if (flags & RTC_OBJ_OPTINAL)
			(void) strcat(string, MSG_ORIG(MSG_CONF_OPTIONAL));
		else
			(void) strcat(string, MSG_ORIG(MSG_CONF_ALTER));
	}
	if (flags & RTC_OBJ_DUMP)
		(void) strcat(string, MSG_ORIG(MSG_CONF_DUMP));
	if (flags & RTC_OBJ_REALPTH)
		(void) strcat(string, MSG_ORIG(MSG_CONF_REALPATH));
	if (flags & RTC_OBJ_GROUP)
		(void) strcat(string, MSG_ORIG(MSG_CONF_GROUP));
	if (flags & RTC_OBJ_APP)
		(void) strcat(string, MSG_ORIG(MSG_CONF_APP));
	if (flags & RTC_OBJ_CMDLINE)
		(void) strcat(string, MSG_ORIG(MSG_CONF_CMDLINE));
	if (flags & RTC_OBJ_FILTER)
		(void) strcat(string, MSG_ORIG(MSG_CONF_FILTER));
	if (flags & RTC_OBJ_FILTEE)
		(void) strcat(string, MSG_ORIG(MSG_CONF_FILTEE));

	(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

	if (strlen(string) == (MSG_GBL_OSQBRKT_SIZE + MSG_GBL_CSQBRKT_SIZE))
		return (MSG_ORIG(MSG_GBL_NULL));
	else
		return ((const char *)string);
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
conv_upm_string(const char *str, const char *old, const char *new,
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
