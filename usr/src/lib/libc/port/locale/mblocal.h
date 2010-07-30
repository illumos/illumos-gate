/*
 * Copyright (c) 2004 Tim J. Robbins.
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

#ifndef _MBLOCAL_H_
#define	_MBLOCAL_H_

#include "runetype.h"

/*
 * Rune initialization function prototypes.
 */
int	_none_init(_RuneLocale *);
int	_ascii_init(_RuneLocale *);
int	_UTF8_init(_RuneLocale *);
int	_EUC_init(_RuneLocale *);
int	_GB18030_init(_RuneLocale *);
int	_GB2312_init(_RuneLocale *);
int	_GBK_init(_RuneLocale *);
int	_BIG5_init(_RuneLocale *);
int	_MSKanji_init(_RuneLocale *);

/*
 * Conversion function pointers for current encoding.
 */
extern size_t (*__mbrtowc)(wchar_t *_RESTRICT_KYWD,
    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD);
extern int (*__mbsinit)(const mbstate_t *);
extern size_t (*__mbsnrtowcs)(wchar_t *_RESTRICT_KYWD,
    const char **_RESTRICT_KYWD, size_t, size_t, mbstate_t *_RESTRICT_KYWD);

extern size_t (*__wcrtomb)(char *_RESTRICT_KYWD, wchar_t,
    mbstate_t *_RESTRICT_KYWD);

extern size_t (*__wcsnrtombs)(char *_RESTRICT_KYWD,
    const wchar_t **_RESTRICT_KYWD, size_t, size_t, mbstate_t *_RESTRICT_KYWD);

size_t __mbsnrtowcs_std(wchar_t *_RESTRICT_KYWD, const char **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD);
size_t __wcsnrtombs_std(char *_RESTRICT_KYWD, const wchar_t **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD);

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

#endif	/* _MBLOCAL_H_ */
