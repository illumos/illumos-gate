/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * C11 c32rtomb(3C) support.
 *
 * The char32_t type is designed to represent a UTF-32 value. For most locales
 * this is the format of a wide-character; however, that is not always the case.
 * For such locales we must convert between that and its corresponding
 * wide-character locale.
 */

#include "thr_uberdata.h"
#include <locale.h>
#include <wchar.h>
#include <xlocale.h>
#include <uchar.h>
#include <errno.h>
#include <stdbool.h>
#include <langinfo.h>
#include <iconv.h>
#include <endian.h>
#include "unicode.h"

static mbstate_t c32rtomb_state;

/*
 * Convert the given UTF-32 wide character into the locale-specific variant.
 * This may require using iconv.
 */
static bool
c32towc(char32_t c32, locale_t loc, wchar_t *wcp)
{
	const char *enc, *inptr;
	int orig_err;
	uint32_t c32_le;
	char buf[MB_CUR_MAX];
	char *outptr;
	size_t inlen, outlen, ret;

	/*
	 * Our UTF-8 locales all use the UTF-32 encoding for the wchar_t so we
	 * can skip this. While ASCII characters do, the character in question
	 * may not be representable in the locale, so we fall through to iconv
	 * for all other cases.
	 */
	enc = nl_langinfo_l(CODESET, loc);
	if (strcmp(enc, "UTF-8") == 0) {
		*wcp = (wchar_t)c32;
		return (true);
	}

	/*
	 * We should not trust iconv and friends not to clobber errno. The spec
	 * expects it is not clobbered here on success, so be paranoid.
	 */
	orig_err = errno;
	iconv_t hdl = iconv_open(enc, "UTF-32LE");
	if (hdl == (iconv_t)-1) {
		return (false);
	}

	c32_le = htole32((uint32_t)c32);
	inptr = (char *)&c32_le;
	inlen = sizeof (c32_le);
	outptr = buf;
	outlen = sizeof (buf);
	ret = iconv(hdl, &inptr, &inlen, &outptr, &outlen);
	(void) iconv_close(hdl);

	/*
	 * We want to make sure we capture both iconv() failing but also it
	 * outputting unknown translations. If there was an unknown translation,
	 * we should fail with EILSEQ rather than proceed.
	 */
	if (ret != 0) {
		return (false);
	}

	/*
	 * We're done with iconv, we can restore errno.
	 */
	errno = orig_err;

	/*
	 * Verify we consumed all of the input and produced some output. Because
	 * we are coming from UTF-32, if it was successfully consumed, then it
	 * should always be consumed. It is possible that it was all consumed,
	 * but no output was produced. In such a case there is nothing we can
	 * really do as this is expected to fully convert a single character in
	 * an invocation.
	 */
	if (inlen != 0 || outlen == sizeof (buf)) {
		return (false);
	}

	/*
	 * We now have a multibyte character array that corresponds to a single
	 * UTF-32 character. However, we cannot just give this back as the
	 * current user mbstate_t may have a shift sequence encoded that would
	 * need to be shifted back. So we must turn this back into a wide
	 * character. We use a single state here. The unfortunate thing here is
	 * we need to maintain the illusion of a single character. So if we
	 * encounter a case where we get multiple wide characters back, we fail.
	 * Hopefully this is a rare case as the majority of used locales are
	 * UTF-8 based so we won't end up here.
	 */
	mbstate_t state = { 0 };
	inlen = sizeof (buf) - outlen;
	ret = mbrtowc_l(wcp, buf, inlen, &state, loc);
	if (ret == (size_t)-1 || (ret > 0 && ret != inlen)) {
		return (false);
	}

	return (true);
}

size_t
c32rtomb_l(char *restrict str, char32_t c32, mbstate_t *restrict ps,
    locale_t restrict loc)
{
	const char *enc;
	wchar_t wc;

	if ((c32 >= UNICODE_SUR_MIN && c32 <= UNICODE_SUR_MAX) ||
	    c32 > UNICODE_SUP_MAX) {
		errno = EILSEQ;
		return ((size_t)-1);
	}

	if (ps == NULL) {
		ps = &c32rtomb_state;
	}

	if (str == NULL) {
		c32 = L'\0';
	}

	if (!c32towc(c32, loc, &wc)) {
		/*
		 * This is an unfortunate error, but the only one the
		 * standard allows us. Though other implementations
		 * definitely return more helpful errors.
		 */
		errno = EILSEQ;
		return ((size_t)-1);
	}

	return (wcrtomb_l(str, wc, ps, loc));
}

size_t
c32rtomb(char *restrict str, char32_t c32, mbstate_t *restrict ps)
{
	return (c32rtomb_l(str, c32, ps, __curlocale()));
}
