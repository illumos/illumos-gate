/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2001, 2003 Alexey Zelkin <phantom@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

#include "lnumeric.h"
#include "lmessages.h"
#include "lmonetary.h"
#include "timelocal.h"
#include "localeimpl.h"

#define	_REL(BASE) ((int)item-BASE)

#pragma weak _nl_langinfo = nl_langinfo

char *
nl_langinfo_l(nl_item item, locale_t loc)
{
	char *ret, *s, *cs;
	struct locdata *ldata;
	const struct lc_monetary *lmon = loc->monetary;
	const struct lc_numeric *lnum = loc->numeric;
	const struct lc_messages *lmsgs = loc->messages;
	const struct lc_time *ltime = loc->time;

	switch (item) {
	case CODESET:
		ret = "";
		/*
		 * The codeset is the suffix of a locale, for most it will
		 * will be UTF-8, as in "en_US.UTF-8".  Short form locales are
		 * not supported.  Note also that although FreeBSD uses
		 * US-ASCII, Solaris historically has reported "646" for the
		 * C locale.
		 *
		 * Note that this code will need to change if we ever support
		 * POSIX defined locale variants (suffixes with an @ sign)
		 */
		ldata = loc->locdata[LC_CTYPE];
		s = ldata ? ldata->l_lname : NULL;
		if (s != NULL) {
			if ((cs = strchr(s, '.')) != NULL)
				ret = cs + 1;
			else if (strcmp(s, "C") == 0 || strcmp(s, "POSIX") == 0)
				ret = "646";
		}
		break;
	case D_T_FMT:
		ret = (char *)ltime->c_fmt;
		break;
	case D_FMT:
		ret = (char *)ltime->x_fmt;
		break;
	case T_FMT:
		ret = (char *)ltime->X_fmt;
		break;
	case T_FMT_AMPM:
		ret = (char *)ltime->ampm_fmt;
		break;
	case AM_STR:
		ret = (char *)ltime->am;
		break;
	case PM_STR:
		ret = (char *)ltime->pm;
		break;
	case DAY_1: case DAY_2: case DAY_3:
	case DAY_4: case DAY_5: case DAY_6: case DAY_7:
		ret = (char *)ltime->weekday[_REL(DAY_1)];
		break;
	case ABDAY_1: case ABDAY_2: case ABDAY_3:
	case ABDAY_4: case ABDAY_5: case ABDAY_6: case ABDAY_7:
		ret = (char *)ltime->wday[_REL(ABDAY_1)];
		break;
	case MON_1: case MON_2: case MON_3: case MON_4:
	case MON_5: case MON_6: case MON_7: case MON_8:
	case MON_9: case MON_10: case MON_11: case MON_12:
		ret = (char *)ltime->month[_REL(MON_1)];
		break;
	case ABMON_1: case ABMON_2: case ABMON_3: case ABMON_4:
	case ABMON_5: case ABMON_6: case ABMON_7: case ABMON_8:
	case ABMON_9: case ABMON_10: case ABMON_11: case ABMON_12:
		ret = (char *)ltime->mon[_REL(ABMON_1)];
		break;
	case ERA:
		/* XXX: need to be implemented  */
		ret = "";
		break;
	case ERA_D_FMT:
		/* XXX: need to be implemented  */
		ret = "";
		break;
	case ERA_D_T_FMT:
		/* XXX: need to be implemented  */
		ret = "";
		break;
	case ERA_T_FMT:
		/* XXX: need to be implemented  */
		ret = "";
		break;
	case ALT_DIGITS:
		/* XXX: need to be implemented  */
		ret = "";
		break;
	case RADIXCHAR:
		ret = (char *)lnum->decimal_point;
		break;
	case THOUSEP:
		ret = (char *)lnum->thousands_sep;
		break;
	case YESEXPR:
		ret = (char *)lmsgs->yesexpr;
		break;
	case NOEXPR:
		ret = (char *)lmsgs->noexpr;
		break;
	/*
	 * YESSTR and NOSTR items were removed from Issue 7.  But
	 * older applications might still need them.  Their use is
	 * discouraged.
	 */
	case YESSTR:	/* LEGACY  */
		ret = (char *)lmsgs->yesstr;
		break;
	case NOSTR:	/* LEGACY  */
		ret = (char *)lmsgs->nostr;
		break;
	/*
	 * SUSv2 special formatted currency string
	 */
	case CRNCYSTR:
		ret = lmon->crncystr;
		break;

	case _DATE_FMT:		/* Solaris specific extension */
		ret = (char *)ltime->date_fmt;
		break;
	/*
	 * Note that FreeBSD also had a private D_MD_ORDER, but that appears
	 * to have been specific to FreeBSD, so we have not included it here.
	 */
	default:
		ret = "";
	}
	return (ret);
}

char *
nl_langinfo(nl_item item)
{
	return (nl_langinfo_l(item, uselocale(NULL)));
}
