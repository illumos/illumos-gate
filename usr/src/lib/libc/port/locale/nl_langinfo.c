/*
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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#define	_REL(BASE) ((int)item-BASE)

#define	MONETARY	(__get_current_monetary_locale())
#define	TIME		(__get_current_time_locale())
#define	MESSAGES	(__get_current_messages_locale())
#define	NUMERIC		(__get_current_numeric_locale())

#pragma weak _nl_langinfo = nl_langinfo

char *
nl_langinfo(nl_item item)
{
	char *ret, *s, *cs;
	static char *csym = NULL;

	switch (item) {
	case CODESET:
		ret = "";
		/*
		 * The codeset is the suffix of a locale, for most it will
		 * will be UTF-8, as in "en.UTF-8".  Short form locales are
		 * not supported.  Note also that although FreeBSD uses
		 * US-ASCII, Solaris historically has reported "646" for the
		 * C locale.
		 */
		if ((s = setlocale(LC_CTYPE, NULL)) != NULL) {
			if ((cs = strchr(s, '.')) != NULL)
				ret = cs + 1;
			else if (strcmp(s, "C") == 0 || strcmp(s, "POSIX") == 0)
				ret = "646";
		}
		break;
	case D_T_FMT:
		ret = (char *)TIME->c_fmt;
		break;
	case D_FMT:
		ret = (char *)TIME->x_fmt;
		break;
	case T_FMT:
		ret = (char *)TIME->X_fmt;
		break;
	case T_FMT_AMPM:
		ret = (char *)TIME->ampm_fmt;
		break;
	case AM_STR:
		ret = (char *)TIME->am;
		break;
	case PM_STR:
		ret = (char *)TIME->pm;
		break;
	case DAY_1: case DAY_2: case DAY_3:
	case DAY_4: case DAY_5: case DAY_6: case DAY_7:
		ret = (char *)TIME->weekday[_REL(DAY_1)];
		break;
	case ABDAY_1: case ABDAY_2: case ABDAY_3:
	case ABDAY_4: case ABDAY_5: case ABDAY_6: case ABDAY_7:
		ret = (char *)TIME->wday[_REL(ABDAY_1)];
		break;
	case MON_1: case MON_2: case MON_3: case MON_4:
	case MON_5: case MON_6: case MON_7: case MON_8:
	case MON_9: case MON_10: case MON_11: case MON_12:
		ret = (char *)TIME->month[_REL(MON_1)];
		break;
	case ABMON_1: case ABMON_2: case ABMON_3: case ABMON_4:
	case ABMON_5: case ABMON_6: case ABMON_7: case ABMON_8:
	case ABMON_9: case ABMON_10: case ABMON_11: case ABMON_12:
		ret = (char *)TIME->mon[_REL(ABMON_1)];
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
		ret = (char *)NUMERIC->decimal_point;
		break;
	case THOUSEP:
		ret = (char *)NUMERIC->thousands_sep;
		break;
	case YESEXPR:
		ret = (char *)MESSAGES->yesexpr;
		break;
	case NOEXPR:
		ret = (char *)MESSAGES->noexpr;
		break;
	/*
	 * YESSTR and NOSTR items marked with LEGACY are available, but not
	 * recomended by SUSv2 to be used in portable applications since
	 * they're subject to remove in future specification editions.
	 */
	case YESSTR:	/* LEGACY  */
		ret = (char *)MESSAGES->yesstr;
		break;
	case NOSTR:	/* LEGACY  */
		ret = (char *)MESSAGES->nostr;
		break;
	/*
	 * SUSv2 special formatted currency string
	 */
	case CRNCYSTR:
		ret = "";
		cs = (char *)MONETARY->currency_symbol;
		if (*cs != '\0') {
			char pos = localeconv()->p_cs_precedes;

			if (pos == localeconv()->n_cs_precedes) {
				char psn = '\0';

				if (pos == CHAR_MAX) {
					if (strcmp(cs,
					    MONETARY->mon_decimal_point) == 0)
						psn = '.';
				} else
					psn = pos ? '-' : '+';
				if (psn != '\0') {
					int clen = strlen(cs);
					char *newc;

					newc = realloc(csym, clen + 2);
					if (newc != NULL) {
						free(csym);
						csym = newc;
						*csym = psn;
						(void) strcpy(csym + 1, cs);
						ret = csym;
					}
				}
			}
		}
		break;
	case _DATE_FMT:		/* Solaris specific extension */
		ret = (char *)TIME->date_fmt;
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
