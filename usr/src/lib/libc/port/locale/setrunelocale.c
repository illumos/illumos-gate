/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include "file64.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>
#include "runetype.h"
#include "ldpart.h"
#include "mblocal.h"
#include "setlocale.h"
#include "_ctype.h"
#include "../i18n/_locale.h"

extern _RuneLocale	*_Read_RuneMagi(FILE *);
extern unsigned char	__ctype_C[];

static int		__setrunelocale(const char *);

static int
__setrunelocale(const char *encoding)
{
	FILE *fp;
	char name[PATH_MAX];
	_RuneLocale *rl;
	int saverr, ret;
	size_t (*old__mbrtowc)(wchar_t *_RESTRICT_KYWD,
	    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD);
	size_t (*old__wcrtomb)(char *_RESTRICT_KYWD, wchar_t,
	    mbstate_t *_RESTRICT_KYWD);
	int (*old__mbsinit)(const mbstate_t *);
	size_t (*old__mbsnrtowcs)(wchar_t *_RESTRICT_KYWD,
	    const char **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);
	size_t (*old__wcsnrtombs)(char *_RESTRICT_KYWD,
	    const wchar_t **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);
	static char ctype_encoding[ENCODING_LEN + 1];
	static _RuneLocale *CachedRuneLocale;
	static size_t (*Cached__mbrtowc)(wchar_t *_RESTRICT_KYWD,
	    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD);
	static size_t (*Cached__wcrtomb)(char *_RESTRICT_KYWD, wchar_t,
	    mbstate_t *_RESTRICT_KYWD);
	static int (*Cached__mbsinit)(const mbstate_t *);
	static size_t (*Cached__mbsnrtowcs)(wchar_t *_RESTRICT_KYWD,
	    const char **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);
	static size_t (*Cached__wcsnrtombs)(char *_RESTRICT_KYWD,
	    const wchar_t **_RESTRICT_KYWD, size_t, size_t,
	    mbstate_t *_RESTRICT_KYWD);

	/*
	 * The "C" and "POSIX" locale are always here.
	 */
	if (strcmp(encoding, "C") == 0 || strcmp(encoding, "POSIX") == 0) {
		int i;

		(void) memcpy(__ctype, __ctype_C, SZ_TOTAL);

		for (i = 0; i < _CACHED_RUNES; i++) {
			__ctype_mask[i] = _DefaultRuneLocale.__runetype[i];
			__trans_upper[i] = _DefaultRuneLocale.__mapupper[i];
			__trans_lower[i] = _DefaultRuneLocale.__maplower[i];
		}

		(void) _none_init(&_DefaultRuneLocale);
		return (0);
	}

	/*
	 * If the locale name is the same as our cache, use the cache.
	 */
	if (CachedRuneLocale != NULL &&
	    strcmp(encoding, ctype_encoding) == 0) {
		_CurrentRuneLocale = CachedRuneLocale;
		__mbrtowc = Cached__mbrtowc;
		__mbsinit = Cached__mbsinit;
		__mbsnrtowcs = Cached__mbsnrtowcs;
		__wcrtomb = Cached__wcrtomb;
		__wcsnrtombs = Cached__wcsnrtombs;
		return (0);
	}

	/*
	 * Slurp the locale file into the cache.
	 */

	(void) snprintf(name, sizeof (name), "%s/%s/LC_CTYPE/LCL_DATA",
	    _PathLocale, encoding);

	if ((fp = fopen(name, "r")) == NULL)
		return (errno == 0 ? ENOENT : errno);

	if ((rl = _Read_RuneMagi(fp)) == NULL) {
		saverr = (errno == 0 ? EINVAL : errno);
		(void) fclose(fp);
		return (saverr);
	}
	(void) fclose(fp);

	old__mbrtowc = __mbrtowc;
	old__mbsinit = __mbsinit;
	old__mbsnrtowcs = __mbsnrtowcs;
	old__wcrtomb = __wcrtomb;
	old__wcsnrtombs = __wcsnrtombs;

	__mbrtowc = NULL;
	__mbsinit = NULL;
	__mbsnrtowcs = __mbsnrtowcs_std;
	__wcrtomb = NULL;
	__wcsnrtombs = __wcsnrtombs_std;

	if (strcmp(rl->__encoding, "NONE") == 0)
		ret = _none_init(rl);
	else if (strcmp(rl->__encoding, "ASCII") == 0)
		ret = _ascii_init(rl);
	else if (strcmp(rl->__encoding, "UTF-8") == 0)
		ret = _UTF8_init(rl);
	else if (strcmp(rl->__encoding, "EUC-CN") == 0)
		ret = _EUC_CN_init(rl);
	else if (strcmp(rl->__encoding, "EUC-JP") == 0)
		ret = _EUC_JP_init(rl);
	else if (strcmp(rl->__encoding, "EUC-KR") == 0)
		ret = _EUC_KR_init(rl);
	else if (strcmp(rl->__encoding, "EUC-TW") == 0)
		ret = _EUC_TW_init(rl);
	else if (strcmp(rl->__encoding, "GB18030") == 0)
		ret = _GB18030_init(rl);
	else if (strcmp(rl->__encoding, "GB2312") == 0)
		ret = _GB2312_init(rl);
	else if (strcmp(rl->__encoding, "GBK") == 0)
		ret = _GBK_init(rl);
	else if (strcmp(rl->__encoding, "BIG5") == 0)
		ret = _BIG5_init(rl);
	else if (strcmp(rl->__encoding, "MSKanji") == 0)
		ret = _MSKanji_init(rl);
	else
		ret = EINVAL;

	if (ret == 0) {
		if (CachedRuneLocale != NULL) {
			free(CachedRuneLocale);
		}
		CachedRuneLocale = _CurrentRuneLocale;
		Cached__mbrtowc = __mbrtowc;
		Cached__mbsinit = __mbsinit;
		Cached__mbsnrtowcs = __mbsnrtowcs;
		Cached__wcrtomb = __wcrtomb;
		Cached__wcsnrtombs = __wcsnrtombs;
		(void) strcpy(ctype_encoding, encoding);

		/*
		 * We need to overwrite the _ctype array.  This requires
		 * some finagling.  This is because references to it may
		 * have been baked into applications.
		 *
		 * Note that it is interesting that toupper/tolower only
		 * produce defined results when the input is representable
		 * as a byte.
		 */

		/*
		 * The top half is the type mask array.  Because we
		 * want to support both legacy Solaris code (which have
		 * mask valeus baked in to them), and we want to be able
		 * to import locale files from other sources (FreeBSD)
		 * which probably uses different masks, we have to perform
		 * a conversion here.  Ugh.  Note that the _CTYPE definitions
		 * we use from FreeBSD are richer than the Solaris legacy.
		 *
		 * We have to cope with these limitations though, because the
		 * inadequate Solaris definitions were baked into binaries.
		 */
		for (int i = 0; i < _CACHED_RUNES; i++) {
			/* ctype can only encode the lower 8 bits. */
			__ctype[i+1] = rl->__runetype[i] & 0xff;
			__ctype_mask[i] = rl->__runetype[i];
		}

		/* The bottom half is the toupper/lower array */
		for (int i = 0; i < _CACHED_RUNES; i++) {
			__ctype[258 + i] = i;
			if (rl->__mapupper[i] && rl->__mapupper[i] != i)
				__ctype[258+i] = rl->__mapupper[i];
			if (rl->__maplower[i] && rl->__maplower[i] != i)
				__ctype[258+i] = rl->__maplower[i];

			/* Don't forget these annoyances either! */
			__trans_upper[i] = rl->__mapupper[i];
			__trans_lower[i] = rl->__maplower[i];
		}

		/*
		 * Note that we expect the init code will have populated
		 * the CSWIDTH array (__ctype[514-520]) properly.
		 */
	} else {
		__mbrtowc = old__mbrtowc;
		__mbsinit = old__mbsinit;
		__mbsnrtowcs = old__mbsnrtowcs;
		__wcrtomb = old__wcrtomb;
		__wcsnrtombs = old__wcsnrtombs;
		free(rl);
	}

	return (ret);
}

int
__wrap_setrunelocale(const char *locale)
{
	int ret = __setrunelocale(locale);

	if (ret != 0) {
		errno = ret;
		return (_LDP_ERROR);
	}
	return (_LDP_LOADED);
}
