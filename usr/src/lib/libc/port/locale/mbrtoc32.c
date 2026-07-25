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
 * C11 mbrtoc32(3C) support.
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
#include <langinfo.h>
#include <iconv.h>
#include <endian.h>

static mbstate_t mbrtoc32_state;

/*
 * Mechanically, we are receiving a series of bytes that we need to convert to a
 * UTF-32 character. This conversion may require us to use iconv if we are not
 * dealing with a unicode based encoding. In general, our process here is to
 * first go through and consume characters until we get a valid wide character.
 *
 * Once we have a valid wide character, we convert it into UTF-32 characters.
 * Only once we have that can we go ahead and actually store this back to the
 * user. If the locale uses UTF-32 as its natural wide-character encoding, then
 * we skip the iconv.
 */
size_t
mbrtoc32_l(char32_t *restrict pc32, const char *restrict str, size_t len,
    mbstate_t *restrict ps, locale_t restrict loc)
{
	const char *enc, *inptr;
	char *outptr;
	int orig_err;
	size_t ret, inlen, outlen, ic_ret;
	wchar_t wc;
	char32_t out_le;
	char in[MB_CUR_MAX];

	if (ps == NULL) {
		ps = &mbrtoc32_state;
	}

	if (str == NULL) {
		pc32 = NULL;
		str = "";
		len = 1;
	}

	ret = mbrtowc_l(&wc, str, len, ps, loc);
	switch (ret) {
	case 0:
		if (pc32 != NULL)
			*pc32 = 0;
		return (ret);
	case (size_t)-1:
	case (size_t)-2:
		return (ret);
	case (size_t)-3:
	default:
		break;
	}

	/*
	 * We have a complete character. See if we need to perform a conversion.
	 */
	enc = nl_langinfo_l(CODESET, loc);
	if (strcmp(enc, "UTF-8") == 0) {
		if (pc32 != NULL)
			*pc32 = wc;
		return (ret);
	}

	/*
	 * We have more work to do. Convert this wide character now into a valid
	 * multi-byte character so we can convert it with iconv.
	 */
	mbstate_t state = { 0 };
	inlen = wcrtomb_l(in, wc, &state, loc);
	if (inlen == (size_t)-1) {
		return (inlen);
	}

	/*
	 * We should not trust iconv and friends not to clobber errno. The spec
	 * expects it is not clobbered here on success, so be paranoid.
	 */
	orig_err = errno;
	iconv_t hdl = iconv_open("UTF-32LE", enc);
	if (hdl == (iconv_t)-1) {
		/*
		 * Unfortunately the only legal error to return here is EILSEQ;
		 * however, that can definitely be misleading.
		 */
		errno = EILSEQ;
		return ((size_t)-1);
	}


	inptr = in;
	outptr = (char *)&out_le;
	outlen = sizeof (out_le);
	ic_ret = iconv(hdl, &inptr, &inlen, &outptr, &outlen);
	(void) iconv_close(hdl);

	/*
	 * We want to make sure we capture both iconv() failing but also it
	 * outputting unknown translations. If there was an unknown translation,
	 * we should fail with EILSEQ rather than proceed.
	 */
	if (ic_ret != 0) {
		errno = EILSEQ;
		return (ic_ret);
	}

	/*
	 * We're done with iconv, we can restore errno.
	 */
	errno = orig_err;

	/*
	 * Verify we produced a single UTF-32 character worth of output.
	 */
	if (outlen != 0) {
		errno = EILSEQ;
		return ((size_t)-1);
	}

	/*
	 * Now that we have a valid character, we can go ahead and give it back
	 * to the user. We need to return the number of characters that we
	 * actually consumed. One caveat is that if we got a null character,
	 * then the expected return value is zero.
	 */
	if (out_le == 0)
		ret = 0;
	if (pc32 != NULL)
		*pc32 = letoh32(out_le);
	return (ret);
}

size_t
mbrtoc32(char32_t *restrict pc32, const char *restrict str, size_t len,
    mbstate_t *restrict ps)
{
	return (mbrtoc32_l(pc32, str, len, ps, __curlocale()));
}
