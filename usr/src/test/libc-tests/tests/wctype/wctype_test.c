/*
 * Copyright (c) 2014 Lauri Tirkkonen <lotheac@iki.fi>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This program tests that the characters defined in the POSIX-1.2008 Portable
 * Character Set are classified correctly by the iswctype and isw* functions.
 */

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>
#include <err.h>
#include "test_common.h"

wint_t upper_should[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
wint_t lower_should[] = L"abcdefghijklmnopqrstuvwxyz";
wint_t digit_should[] = L"0123456789";
wint_t space_should[] = L"\t\n\v\f\r ";
wint_t cntrl_should[] = L"\a\b\t\n\v\f\r\0\001\002\003\004\005\006\016\017\020"
"\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037";
wint_t punct_should[] = L"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
wint_t xdigit_should[] = L"0123456789ABCDEFabcdef";
wint_t blank_should[] = L" \t";
wint_t only_space_should[] = L" ";

#define	test_ctype_subset(x, y) do {\
	test_t t = test_start(#x "_should is subset of " #y);\
	wctype_t class = wctype(#y);\
	if (!class) test_failed(t, "wctype(\"%s\") returned 0", #y);\
	size_t nchars = (sizeof (x ## _should) / sizeof (*x ## _should)) - 1;\
	for (wint_t *wc = x ## _should; wc < x ## _should + nchars; wc++) {\
		if (!iswctype(*wc, class))\
			test_failed(t, "iswctype(L'%lc', wctype(\"%s\"))"\
				    "returned 0", *wc, #y);\
		if (!isw ## y(*wc))\
			test_failed(t, "isw%s(L'%lc') returned 0", #y, *wc);\
	}\
	test_passed(t);\
} while (*"\0")

#define	test_ctype(x) test_ctype_subset(x, x)

int main(void) {
	if (!setlocale(LC_CTYPE, "POSIX"))
		err(1, "setlocale POSIX failed");
	test_ctype(upper);
	test_ctype(lower);
	test_ctype(digit);
	test_ctype(space);
	test_ctype(cntrl);
	test_ctype(punct);
	test_ctype(xdigit);
	test_ctype(blank);

	test_ctype_subset(upper, alpha);
	test_ctype_subset(lower, alpha);
	test_ctype_subset(upper, alnum);
	test_ctype_subset(lower, alnum);
	test_ctype_subset(digit, alnum);
	test_ctype_subset(upper, print);
	test_ctype_subset(lower, print);
	test_ctype_subset(digit, print);
	test_ctype_subset(punct, print);
	test_ctype_subset(only_space, print);
	test_ctype_subset(upper, graph);
	test_ctype_subset(lower, graph);
	test_ctype_subset(digit, graph);
	test_ctype_subset(punct, graph);
	return (0);
}
