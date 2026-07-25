/*
 * Copyright 2026 Oxide Computer Company
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
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

#ifndef _MBLOCAL_H_
#define	_MBLOCAL_H_

#include "runetype.h"
#include "lctype.h"
#include <uchar.h>

/*
 * Actual implementation structures for mbstate_t data.
 *
 * All of the conversion states are independent of one another, with the
 * exception of those used for the C standard unicode transformations:
 * c8rtomb(), c16rtomb(), mbrtoc8(), and mbrtoc16(). These need state to be able
 * to consume and handle their own intermediate representations (e.g. UTF-16
 * surrogate pairs) as well as all of the state to convert them to and from the
 * corresponding wide character format in their own locale. To simplify things,
 * these have a union of all the existing required state and then their own
 * additional state.
 */
typedef struct {
	wchar_t	ch;
} _BIG5State;

typedef struct {
	wchar_t	ch;
	int	set;
	int	want;
} _EucState;

typedef struct {
	int	count;
	uchar_t	bytes[4];
} _GB18030State;

typedef struct {
	int	count;
	uchar_t	bytes[2];
} _GB2312State;

typedef struct {
	wchar_t	ch;
} _GBKState;

typedef struct {
	wchar_t	ch;
} _MSKanjiState;

typedef struct {
	wchar_t	ch;
	int	want;
	wchar_t	lbound;
} _UTF8State;

typedef struct {
	union {
		_BIG5State	c16_big5;
		_EucState	c16_euc;
		_GB18030State	c16_gb18030;
		_GB2312State	c16_gb2312;
		_GBKState	c16_gbk;
		_MSKanjiState	c16_mskanji;
		_UTF8State	c16_utf8;
	} c16_state;
	char16_t c16_surrogate;
} _CHAR16State;

typedef struct {
	union {
		_BIG5State	c16_big5;
		_EucState	c16_euc;
		_GB18030State	c16_gb18030;
		_GB2312State	c16_gb2312;
		_GBKState	c16_gbk;
		_MSKanjiState	c16_mskanji;
		_UTF8State	c16_utf8;
	} c8_state;
	char8_t c8_bytes[4];
	uint8_t c8_count:4;
	uint8_t c8_exp:4;
} _CHAR8State;

/*
 * Rune initialization function prototypes.
 */
void	_none_init(struct lc_ctype *);
void	_UTF8_init(struct lc_ctype *);
void	_EUC_CN_init(struct lc_ctype *);
void	_EUC_JP_init(struct lc_ctype *);
void	_EUC_KR_init(struct lc_ctype *);
void	_EUC_TW_init(struct lc_ctype *);
void	_GB18030_init(struct lc_ctype *);
void	_GB2312_init(struct lc_ctype *);
void	_GBK_init(struct lc_ctype *);
void	_BIG5_init(struct lc_ctype *);
void	_MSKanji_init(struct lc_ctype *);

typedef size_t (*mbrtowc_pfn_t)(wchar_t *_RESTRICT_KYWD,
    const char *_RESTRICT_KYWD, size_t, mbstate_t *_RESTRICT_KYWD, boolean_t);
typedef size_t (*wcrtomb_pfn_t)(char *_RESTRICT_KYWD, wchar_t,
    mbstate_t *_RESTRICT_KYWD);
size_t __mbsnrtowcs_std(wchar_t *_RESTRICT_KYWD, const char **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD, mbrtowc_pfn_t);
size_t __wcsnrtombs_std(char *_RESTRICT_KYWD, const wchar_t **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD, wcrtomb_pfn_t);

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

#endif	/* _MBLOCAL_H_ */
