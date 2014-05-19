/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
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
#include "lctype.h"
#include "localeimpl.h"

extern _RuneLocale	*_Read_RuneMagi(const char *);

struct lc_ctype lc_ctype_posix = {
	.lc_mbrtowc = __mbrtowc_ascii,
	.lc_mbsinit = __mbsinit_ascii,
	.lc_mbsnrtowcs = __mbsnrtowcs_ascii,
	.lc_wcrtomb = __wcrtomb_ascii,
	.lc_wcsnrtombs = __wcsnrtombs_ascii,
	.lc_is_ascii = 1,
	.lc_max_mblen = 1,
	.lc_trans_upper = _DefaultRuneLocale.__mapupper,
	.lc_trans_lower = _DefaultRuneLocale.__maplower,
	.lc_ctype_mask = _DefaultRuneLocale.__runetype,
};

struct locdata __posix_ctype_locdata = {
	.l_lname = "C",
	.l_data = { &lc_ctype_posix, &_DefaultRuneLocale }
};


/*
 * Table of initializers for encodings.  When you add a new encoding type,
 * this table should be updated.
 */
static struct {
	const char *e_name;
	void (*e_init)(struct lc_ctype *);
} encodings[] = {
	{ "NONE", _none_init },
	{ "UTF-8",	_UTF8_init },
	{ "EUC-CN",	_EUC_CN_init },
	{ "EUC-JP",	_EUC_JP_init },
	{ "EUC-KR",	_EUC_KR_init },
	{ "EUC-TW",	_EUC_TW_init },
	{ "GB18030",	_GB18030_init },
	{ "GB2312",	_GB2312_init },
	{ "GBK",	_GBK_init },
	{ "BIG5",	_BIG5_init },
	{ "MSKanji",	_MSKanji_init },
	{ NULL,		NULL }
};


struct locdata *
__lc_ctype_load(const char *name)
{
	struct locdata *ldata;
	struct lc_ctype *lct;
	_RuneLocale *rl;
	int i;
	char path[PATH_MAX];

	if ((ldata = __locdata_alloc(name, sizeof (*lct))) == NULL)
		return (NULL);
	lct = ldata->l_data[0];
	/*
	 * Slurp the locale file into the cache.
	 */

	(void) snprintf(path, sizeof (path), "%s/%s/LC_CTYPE/LCL_DATA",
	    _PathLocale, name);

	if ((rl = _Read_RuneMagi(path)) == NULL) {
		__locdata_free(ldata);
		errno = EINVAL;
		return (NULL);
	}
	ldata->l_data[1] = rl;

	lct->lc_mbrtowc = NULL;
	lct->lc_mbsinit = NULL;
	lct->lc_mbsnrtowcs = NULL;
	lct->lc_wcrtomb = NULL;
	lct->lc_wcsnrtombs = NULL;
	lct->lc_ctype_mask = rl->__runetype;
	lct->lc_trans_upper = rl->__mapupper;
	lct->lc_trans_lower = rl->__maplower;

	/* set up the function pointers */
	for (i = 0; encodings[i].e_name != NULL; i++) {
		int l = strlen(encodings[i].e_name);
		if ((strncmp(rl->__encoding, encodings[i].e_name, l) == 0) &&
		    (rl->__encoding[l] == '\0' || rl->__encoding[l] == '@')) {
			encodings[i].e_init(lct);
			break;
		}
	}
	if (encodings[i].e_name == NULL) {
		__locdata_free(ldata);
		errno = EINVAL;
		return (NULL);
	}


	return (ldata);
}
