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
 * Test the implementation of various pieces of uchar.h(3HEAD) functionality.
 */

#include <locale.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <strings.h>
#include <wchar.h>
#include <uchar.h>
#include <errno.h>
#include <string.h>

static const char *uchar_wide = "光";
static const char32_t uchar_value = 0x5149;
static const char *uchar_hello = "hello";
static const char16_t uchar_euro = 0x20ac;

static void
update_locale(const char *loc)
{
	const char *newloc = setlocale(LC_CTYPE, loc);
	if (newloc == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: failed to update locale to %s",
		    loc);
	}

	if (strcmp(newloc, loc) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: locale set to %s, but got %s",
		    loc, newloc);
	}
}

static boolean_t
mbrtoc32_ascii(mbstate_t *mbs)
{
	char32_t out;
	size_t len;
	boolean_t ret = B_TRUE;

	if ((len = mbrtoc32(&out, uchar_hello, 5, mbs)) != 1) {
		warnx("expected mbrtoc32 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'h') {
		warnx("got bad char32_t, expected 0x%x, found 0x%x", 'h',
		    out);
		ret = B_FALSE;
	}

	if ((len = mbrtoc32(&out, uchar_hello + 1, 4, mbs)) != 1) {
		warnx("expected mbrtoc32 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'e') {
		warnx("got bad char32_t, expected 0x%x, found 0x%x", 'h',
		    out);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_ascii_internal(void)
{
	return (mbrtoc32_ascii(NULL));
}

static boolean_t
mbrtoc32_ascii_mbstate(void)
{
	mbstate_t mbs;

	bzero(&mbs, sizeof (mbs));
	return (mbrtoc32_ascii(&mbs));
}

static boolean_t
mbrtoc32_badseq_utf8(void)
{
	mbstate_t mbs;
	size_t len;
	char32_t out;
	boolean_t ret = B_TRUE;
	char *badstr;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, "\xa9", 1, &mbs);
	if (len != (size_t)-1) {
		warnx("mbrtoc32 returned %zu, not %zu", len, (size_t)-1);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	badstr = strdup(uchar_wide);
	if (badstr == NULL) {
		warn("failed to duplicate uchar_wide");
		return (B_FALSE);
	}

	badstr[1] = '?';
	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, badstr, strlen(badstr), &mbs);
	free(badstr);
	if (len != (size_t)-1) {
		warnx("mbrtoc32 returned %zu, not %zu", len, (size_t)-1);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_badseq_8859(void)
{
	mbstate_t mbs;
	size_t len;
	char32_t out;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, "\x87", 1, &mbs);
	if (len != (size_t)-1) {
		warnx("mbrtoc32 returned %zu, not %zu", len, (size_t)-1);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_roundtrip(void)
{
	char32_t out;
	size_t len, clen;
	mbstate_t mbs;
	char buf[MB_CUR_MAX];
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, uchar_wide, strlen(uchar_wide), &mbs);
	if (len != 3) {
		warnx("mbrtoc32 returned %zu, expected %u", len, 3);
		ret = B_FALSE;
	}

	if (out != uchar_value) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out, uchar_value);
		ret = B_FALSE;
	}

	bzero(&mbs, sizeof (mbs));
	clen = c32rtomb(buf, out, &mbs);
	if (clen != len) {
		warnx("c32rtomb returned %zu bytes, but we originally used %zu",
		    clen, len);
		ret = B_FALSE;
	}

	if (strncmp(buf, uchar_wide, len) != 0) {
		warnx("round trip string comparison failed");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_partial(void)
{
	char32_t out;
	size_t len, i;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	for (i = 0; i < strlen(uchar_wide) - 1; i++) {
		len = mbrtoc32(&out, uchar_wide + i, 1, &mbs);
		if (len != (size_t)-2) {
			warnx("partial mbrtoc32 returned %zu, not -2", len);
			ret = B_FALSE;
		}
	}

	len = mbrtoc32(&out, uchar_wide + i, 1, &mbs);
	if (len != 1) {
		warnx("partial mbrtoc32 returned %zu, not 1", len);
		ret = B_FALSE;
	}

	if (out != uchar_value) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out, uchar_value);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_zero(void)
{
	char32_t out, exp = L'\0';
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, "", 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc32 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_zero_len(void)
{
	char32_t out = 0x12345, exp = 0x12345;
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, uchar_wide, 0, &mbs);
	if (len != (size_t)-2) {
		warnx("partial mbrtoc32 returned %zu, not -2", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc32 incorrectly wrote to char32_t value with "
		    "zero string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc32_null(void)
{
	char32_t out = 0x123456, exp = 0x123456;
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, NULL, 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc32 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc32 incorrectly wrote to char32_t value with "
		    "null string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * Verify that a character string in 8859-1 (which nominally overlaps with UTF)
 * can properly go through iconv and come out as what we expect on the other
 * side.
 */
static boolean_t
mbrtoc32_iconv_8859(void)
{
	mbstate_t mbs;
	size_t len;
	char32_t out, exp = L'\xa6';
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, "\xa6", 1, &mbs);
	if (len != 1) {
		warnx("mbrtoc32 returned %zu, not 1", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * Similar to the above but here we actually expect it to be something else
 * entirely and not a 1:1 translation. This verifies that iconv is firing and
 * getting us more than one character.
 */
static boolean_t
mbrtoc32_iconv_euro(void)
{
	mbstate_t mbs;
	size_t len;
	char32_t out, exp = uchar_euro;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc32(&out, "\xa4", 1, &mbs);
	if (len != 1) {
		warnx("mbrtoc32 returned %zu, not 1", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_ascii(mbstate_t *mbs)
{
	char16_t out;
	size_t len;
	boolean_t ret = B_TRUE;

	if ((len = mbrtoc16(&out, uchar_hello, 5, mbs)) != 1) {
		warnx("expected mbrtoc16 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'h') {
		warnx("got bad char16_t, expected 0x%x, found 0x%x", 'h',
		    out);
		ret = B_FALSE;
	}

	if ((len = mbrtoc16(&out, uchar_hello + 1, 4, mbs)) != 1) {
		warnx("expected mbrtoc16 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'e') {
		warnx("got bad char16_t, expected 0x%x, found 0x%x", 'h',
		    out);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_ascii_internal(void)
{
	return (mbrtoc16_ascii(NULL));
}

static boolean_t
mbrtoc16_ascii_mbstate(void)
{
	mbstate_t mbs;

	bzero(&mbs, sizeof (mbs));
	return (mbrtoc16_ascii(&mbs));
}

static boolean_t
mbrtoc16_null(void)
{
	char16_t out = 0x1234, exp = 0x1234;
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc16(&out, NULL, 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc16 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc16 incorrectly wrote to char16_t value with "
		    "null string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_zero(void)
{
	char16_t out, exp = L'\0';
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc16(&out, "", 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc16 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc16 converted character to 0x%x not 0x%x",
		    out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_zero_len(void)
{
	char16_t out = 0x5432, exp = 0x5432;
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc16(&out, uchar_wide, 0, &mbs);
	if (len != (size_t)-2) {
		warnx("partial mbrtoc16 returned %zu, not -2", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc16 incorrectly wrote to char16_t value with "
		    "zero length string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_roundtrip(void)
{
	char16_t out;
	size_t len, clen;
	mbstate_t mbs;
	char buf[MB_CUR_MAX];
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc16(&out, uchar_wide, strlen(uchar_wide), &mbs);
	if (len != 3) {
		warnx("mbrtoc16 returned %zu, expected %u", len, 3);
		ret = B_FALSE;
	}

	if (out != uchar_value) {
		warnx("mbrtoc16 converted character to 0x%x not 0x%x",
		    out, uchar_value);
		ret = B_FALSE;
	}

	clen = c16rtomb(buf, out, &mbs);
	if (clen != len) {
		warnx("c16rtomb returned %zu bytes, but we originally used %zu",
		    clen, len);
		ret = B_FALSE;
	}

	if (strncmp(buf, uchar_wide, len) != 0) {
		warnx("round trip string comparison failed");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_partial(void)
{
	char16_t out;
	size_t len, i;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	for (i = 0; i < strlen(uchar_wide) - 1; i++) {
		len = mbrtoc16(&out, uchar_wide + i, 1, &mbs);
		if (len != (size_t)-2) {
			warnx("partial mbrtoc16 returned %zu, not -2", len);
			ret = B_FALSE;
		}
	}

	len = mbrtoc16(&out, uchar_wide + i, 1, &mbs);
	if (len != 1) {
		warnx("partial mbrtoc16 returned %zu, not 1", len);
		ret = B_FALSE;
	}

	if (out != uchar_value) {
		warnx("mbrtoc16 converted character to 0x%x not 0x%x",
		    out, uchar_value);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc16_surrogate(void)
{
	char16_t out0, out1;
	size_t len, clen;
	mbstate_t mbs;
	const char *surrogate = "\xF0\x9F\x92\xA9";
	char16_t exp0 = 0xd83d, exp1 = 0xdca9;
	size_t slen = strlen(surrogate);
	boolean_t ret = B_TRUE;
	char buf[MB_CUR_MAX];

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc16(&out0, surrogate, slen, &mbs);
	if (len != slen) {
		warnx("mbrtoc16 returned %zu, expected %zu", len, slen);
		ret = B_FALSE;
	}

	if (out0 != exp0) {
		warnx("mbrtoc16 converted character to 0x%x not 0x%x",
		    out0, exp0);
		ret = B_FALSE;
	}

	if (mbsinit(&mbs) != 0) {
		warnx("mb state with a surrogate character is somehow in the "
		    "initial state");
		ret = B_FALSE;
	}

	len = mbrtoc16(&out1, uchar_wide, strlen(uchar_wide), &mbs);
	if (len != (size_t)-3) {
		warnx("mbrtoc16 returned %zu, expected -3", len);
		ret = B_FALSE;
	}

	if (mbsinit(&mbs) == 0) {
		warnx("mb state with after both surrogate characters isn't "
		    "in initial state");
		ret = B_FALSE;
	}

	if (out1 != exp1) {
		warnx("mbrtoc32 converted character to 0x%x not 0x%x",
		    out1, exp1);
		ret = B_FALSE;
	}

	clen = c16rtomb(buf, out0, &mbs);
	if (clen != 0) {
		warnx("c16rtomb returned %zu bytes, but expected zero for the "
		    "first surrogate", clen);
		ret = B_FALSE;
	}

	if (mbsinit(&mbs) != 0) {
		warnx("mb state with a surrogate character is somehow in the "
		    "initial state");
		ret = B_FALSE;
	}

	clen = c16rtomb(buf, out1, &mbs);
	if (clen != slen) {
		warnx("c16rtomb returned %zu, expected %zu", len, slen);
		ret = B_FALSE;
	}

	if (mbsinit(&mbs) == 0) {
		warnx("mb state with after both surrogate characters isn't "
		    "in initial state");
		ret = B_FALSE;
	}

	if (strncmp(buf, surrogate, slen) != 0) {
		warnx("round trip string comparison failed");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c32rtomb_eilseq_iso8859(void)
{
	char buf[MB_CUR_MAX];
	mbstate_t mbs;
	size_t len;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(buf, uchar_value, &mbs);
	if (len != (size_t)-1) {
		warnx("c32rtomb returned %zd, expected -1", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c16rtomb_eilseq_iso8859(void)
{
	char buf[MB_CUR_MAX];
	mbstate_t mbs;
	size_t len;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(buf, (char16_t)uchar_value, &mbs);
	if (len != (size_t)-1) {
		warnx("c32rtomb returned %zd, expected -1", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c32rtomb_eilseq_utf8(void)
{
	char buf[MB_CUR_MAX];
	mbstate_t mbs;
	size_t len;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(buf, UINT32_MAX, &mbs);
	if (len != (size_t)-1) {
		warnx("c32rtomb returned %zd, expected -1", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("found bad errno: expected %s, found %s",
		    strerrorname_np(EILSEQ), strerrorname_np(errno));
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c16rtomb_bad_first(void)
{
	char buf[MB_CUR_MAX];
	mbstate_t mbs;
	size_t len, i;
	char16_t first = 0xd83d;
	char16_t bad[] = { 0x0, 0xd7ff, 0xd83d, 0xd900, 0xffff };
	boolean_t ret = B_TRUE;

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		bzero(&mbs, sizeof (mbs));
		len = c16rtomb(buf, first, &mbs);
		if (len != 0) {
			warnx("c16rtomb returned %zd, expected 0", len);
			ret = B_FALSE;
		}

		len = c16rtomb(buf, bad[i], &mbs);
		if (len != (size_t)-1) {
			warnx("c16rtomb surrogate %x returned %zd, expected "
			    "-1", bad[i], len);
			ret = B_FALSE;
		}

		if (errno != EILSEQ) {
			warnx("found bad errno: expected %s, found %s",
			    strerrorname_np(EILSEQ), strerrorname_np(errno));
			ret = B_FALSE;
		}
	}

	return (ret);
}

static boolean_t
c16rtomb_bad_second(void)
{
	char buf[MB_CUR_MAX];
	mbstate_t mbs;
	size_t len, i;
	char16_t bad[] = { 0xdc00, 0xdd34, 0xdfff };
	boolean_t ret = B_TRUE;

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		bzero(&mbs, sizeof (mbs));
		len = c16rtomb(buf, bad[i], &mbs);
		if (len != (size_t)-1) {
			warnx("c16rtomb surrogate %x returned %zd, expected -1",
			    bad[i], len);
			ret = B_FALSE;
		}

		if (errno != EILSEQ) {
			warnx("found bad errno: expected %s, found %s",
			    strerrorname_np(EILSEQ), strerrorname_np(errno));
			ret = B_FALSE;
		}
	}

	return (ret);
}

static boolean_t
c32rtomb_null(void)
{
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(NULL, uchar_value, &mbs);
	if (len != 1) {
		warnx("c32rtomb returned %zu, expected %d", len, 1);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c32rtomb_null_euro(void)
{
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(NULL, uchar_euro, &mbs);
	if (len != 1) {
		warnx("c32rtomb returned %zu, expected %d", len, 1);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c16rtomb_null(void)
{
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c16rtomb(NULL, uchar_value, &mbs);
	if (len != 1) {
		warnx("c16rtomb returned %zu, expected %d", len, 1);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c16rtomb_null_euro(void)
{
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c16rtomb(NULL, uchar_euro, &mbs);
	if (len != 1) {
		warnx("c16rtomb returned %zu, expected %d", len, 1);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c32rtomb_iconv_ascii(void)
{
	char buf[MB_CUR_MAX];
	const char *exp = "h";
	mbstate_t mbs;
	size_t len;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(buf, L'h', &mbs);
	if (len != 1) {
		warnx("c32rtomb returned %zd, expected 1", len);
		ret = B_FALSE;
	}

	if (strncmp(buf, exp, len) != 0) {
		warnx("c32rtomb didn't return expected string");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c32rtomb_iconv_euro(void)
{
	char buf[MB_CUR_MAX];
	const char *exp = "\xa4";
	mbstate_t mbs;
	size_t len;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = c32rtomb(buf, uchar_euro, &mbs);
	if (len != 1) {
		warnx("c32rtomb returned %zd, expected 1", len);
		ret = B_FALSE;
	}

	if (strncmp(buf, exp, len) != 0) {
		warnx("c32rtomb didn't return expected string");
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * Do a full round trip of our wide character into a full UTF-8 sequence and
 * then back again.
 */
static boolean_t
mbrtoc8_roundtrip(const char *input, size_t inlen, const char8_t *out,
    size_t outlen)
{
	char8_t c8[4];
	size_t exp_mbret[4];
	size_t exp_csret[4];
	char str[MB_CUR_MAX];
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	/*
	 * Construct results based on the given lengths. We will need to call
	 * mbrtoc8 one time for each output character. The first time we call it
	 * though it'll output the input length as it should consume it all. The
	 * opposite is true when we go in reverse.
	 */
	for (size_t i = 0; i < outlen; i++) {
		if (i == 0) {
			exp_mbret[i] = inlen;
		} else {
			exp_mbret[i] = (size_t)-3;
		}
	}

	for (size_t i = 0; i < outlen; i++) {
		if (i == outlen - 1) {
			exp_csret[i] = inlen;
		} else {
			exp_csret[i] = 0;
		}
	}

	bzero(&mbs, sizeof (mbs));
	for (size_t i = 0; i < outlen; i++) {
		size_t len = mbrtoc8(&c8[i], input, inlen, &mbs);
		if (len != exp_mbret[i]) {
			warnx("mbrtoc8[%zu] returned %zu, expected %zd", i, len,
			    exp_mbret[i]);
			ret = B_FALSE;
		}

		if (c8[i] != out[i]) {
			warnx("mbrtoc8[%zu] converted character to 0x%x not "
			    "0x%x", i, c8[i], out[i]);
			ret = B_FALSE;
		}
	}

	bzero(&mbs, sizeof (mbs));
	for (size_t i = 0; i < outlen; i++) {
		size_t len = c8rtomb(str, c8[i], &mbs);
		if (len != exp_csret[i]) {
			warnx("c8rtomb[%zu] returned %zu, expected %zd", i, len,
			    exp_csret[i]);
			ret = B_FALSE;
		}
	}

	if (strncmp(str, input, inlen) != 0) {
		warnx("round trip string comparison failed");
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc8_roundtrip_1b(void)
{
	const char8_t out[1] = { 'h' };
	return (mbrtoc8_roundtrip(uchar_hello, 1, out, ARRAY_SIZE(out)));
}

static boolean_t
mbrtoc8_roundtrip_2b(void)
{
	const char *in = "ũ";
	const char8_t out[2] = { 0xc5, 0xa9 };
	return (mbrtoc8_roundtrip(in, strlen(in), out, ARRAY_SIZE(out)));
}

static boolean_t
mbrtoc8_roundtrip_3b(void)
{
	const char8_t out[3] = { 0xe5, 0x85, 0x89 };
	return (mbrtoc8_roundtrip(uchar_wide, strlen(uchar_wide), out,
	    ARRAY_SIZE(out)));
}

static boolean_t
mbrtoc8_roundtrip_4b(void)
{
	/* U+1B001 */
	const char four[4] = { 0xf0, 0x9b, 0x80, 0x81 };
	const char8_t out[4] = { 0xf0, 0x9b, 0x80, 0x81 };
	return (mbrtoc8_roundtrip(four, ARRAY_SIZE(four), out,
	    ARRAY_SIZE(out)));
}

static boolean_t
mbrtoc8_roundtrip_euro(void)
{
	const char *in = "\xa4";
	const char8_t out[3] = { 0xe2, 0x82, 0xac };
	return (mbrtoc8_roundtrip(in, strlen(in), out, ARRAY_SIZE(out)));
}

typedef struct {
	const char *bu_desc;
	uint8_t bu_nchar;
	char8_t bu_chars[4];
} bad_utf8_t;

/*
 * This covers various bad orderings of characters. See c8rtomb.c in libc. One
 * caveat is that we can't use a 0x00 character in here. That will be
 * interpreted per the standard as a null character regardless of what was
 * already there.
 */
static const bad_utf8_t bad_utf[] = {
	{ "invalid starting (1)", 1, { 0x80 } },
	{ "invalid starting (2)", 1, { 0xff } },
	{ "invalid starting (3)", 1, { 0xc1 } },
	{ "invalid 2-byte (1)", 2, { 0xc2, 0x01 } },
	{ "invalid 2-byte (2)", 2, { 0xc2, 0x42 } },
	{ "invalid 2-byte (3)", 2, { 0xc2, 0xc0 } },
	{ "invalid 2-byte (4)", 2, { 0xdd, 0xdd } },
	{ "invalid 2-byte (5)", 2, { 0xde, 0xed } },
	{ "invalid 2-byte (6)", 2, { 0xdf, 0xfd } },
	{ "invalid 3-byte e0 (1)", 2, { 0xe0, 0x9f } },
	{ "invalid 3-byte e0 (2)", 2, { 0xe0, 0xc0 } },
	{ "invalid 3-byte e0 (3)", 3, { 0xe0, 0xaa, 0x07 } },
	{ "invalid 3-byte e0 (4)", 3, { 0xe0, 0xbf, 0xfb } },
	{ "invalid 3-byte ed (1)", 2, { 0xed, 0x7f } },
	{ "invalid 3-byte ed (2)", 2, { 0xed, 0xa0 } },
	{ "invalid 3-byte ed (3)", 3, { 0xed, 0x98, 0x07 } },
	{ "invalid 3-byte ed (4)", 3, { 0xed, 0x87, 0xcd } },
	{ "invalid 3-byte (1)", 2, { 0xea, 0xea } },
	{ "invalid 3-byte (2)", 2, { 0xe9, 0x23 } },
	{ "invalid 3-byte (3)", 2, { 0xe8, 0xdc } },
	{ "invalid 3-byte (4)", 3, { 0xe8, 0x80, 0x08 } },
	{ "invalid 3-byte (5)", 3, { 0xe8, 0x81, 0xc0 } },
	{ "invalid 3-byte (6)", 3, { 0xe2, 0xaa, 0xce } },
	{ "invalid 4-byte f0 (1)", 2, { 0xf0, 0x89 } },
	{ "invalid 4-byte f0 (2)", 2, { 0xf0, 0x17 } },
	{ "invalid 4-byte f0 (3)", 2, { 0xf0, 0xc0 } },
	{ "invalid 4-byte f0 (4)", 3, { 0xf0, 0x90, 0x23 } },
	{ "invalid 4-byte f0 (5)", 3, { 0xf0, 0x90, 0x42 } },
	{ "invalid 4-byte f0 (6)", 3, { 0xf0, 0xa0, 0xc0 } },
	{ "invalid 4-byte f0 (7)", 3, { 0xf0, 0xb0, 0xdf } },
	{ "invalid 4-byte f0 (9)", 4, { 0xf0, 0xa1, 0x81, 0x18 } },
	{ "invalid 4-byte f0 (10)", 4, { 0xf0, 0x92, 0x82, 0x2b } },
	{ "invalid 4-byte f0 (11)", 4, { 0xf0, 0xa3, 0x92, 0xc9 } },
	{ "invalid 4-byte f0 (12)", 4, { 0xf0, 0xb4, 0xbf, 0xfb } },
	{ "invalid 4-byte f4 (1)", 2, { 0xf4, 0xa2 } },
	{ "invalid 4-byte f4 (2)", 2, { 0xf4, 0x17 } },
	{ "invalid 4-byte f4 (3)", 2, { 0xf4, 0xc0 } },
	{ "invalid 4-byte f4 (4)", 3, { 0xf4, 0x80, 0x23 } },
	{ "invalid 4-byte f4 (5)", 3, { 0xf4, 0x81, 0x42 } },
	{ "invalid 4-byte f4 (6)", 3, { 0xf4, 0x82, 0xc0 } },
	{ "invalid 4-byte f4 (7)", 3, { 0xf4, 0x83, 0xdf } },
	{ "invalid 4-byte f4 (9)", 4, { 0xf4, 0x84, 0x81, 0x18 } },
	{ "invalid 4-byte f4 (10)", 4, { 0xf4, 0x85, 0x82, 0x2b } },
	{ "invalid 4-byte f4 (11)", 4, { 0xf4, 0x86, 0x92, 0xc9 } },
	{ "invalid 4-byte f4 (12)", 4, { 0xf4, 0x87, 0xbf, 0xfb } },
	{ "invalid 4-byte (1)", 2, { 0xf1, 0xcc } },
	{ "invalid 4-byte (2)", 2, { 0xf2, 0x17 } },
	{ "invalid 4-byte (3)", 2, { 0xf3, 0xc0 } },
	{ "invalid 4-byte (4)", 3, { 0xf2, 0x80, 0x23 } },
	{ "invalid 4-byte (5)", 3, { 0xf1, 0x91, 0x42 } },
	{ "invalid 4-byte (6)", 3, { 0xf2, 0xa2, 0xc0 } },
	{ "invalid 4-byte (7)", 3, { 0xf3, 0xb3, 0xdf } },
	{ "invalid 4-byte (9)", 4, { 0xf2, 0xa4, 0x81, 0x18 } },
	{ "invalid 4-byte (10)", 4, { 0xf1, 0x95, 0x82, 0x2b } },
	{ "invalid 4-byte (11)", 4, { 0xf2, 0x86, 0x92, 0xc9 } },
	{ "invalid 4-byte (12)", 4, { 0xf3, 0xa7, 0xbf, 0xfb } },
};

static boolean_t
c8rtomb_bad_utf8(void)
{
	boolean_t ret = B_TRUE;

	for (size_t i = 0; i < ARRAY_SIZE(bad_utf); i++) {
		const bad_utf8_t *t = &bad_utf[i];
		char buf[MB_CUR_MAX];
		mbstate_t mbs = { 0 };
		boolean_t cont = B_TRUE;

		/*
		 * Only the last character in the list should cause a failure.
		 * Make sure all the preceding ones are accepted, but don't
		 * form a complete character.
		 */
		for (size_t c = 0; c < t->bu_nchar - 1; c++) {
			size_t r = c8rtomb(buf, t->bu_chars[c], &mbs);
			if (r != 0) {
				warnx("%s: c8rtomb char[%zu] (0x%x) returned "
				    "%zd, not 0", t->bu_desc, c,
				    t->bu_chars[c], r);
				ret = cont = B_FALSE;
				break;
			}
		}

		if (!cont)
			continue;

		size_t r = c8rtomb(buf, t->bu_chars[t->bu_nchar - 1], &mbs);
		if (r != (size_t)-1) {
			warnx("%s: c8rtomb final char (0x%x) returned %zu, "
			    "not -1", t->bu_desc, t->bu_chars[t->bu_nchar - 1],
			    r);
			ret = B_FALSE;
		} else if (errno != EILSEQ) {
			warnx("%s: c8rtomb failed with %s, not %s", t->bu_desc,
			    strerrorname_np(errno), strerrorname_np(EILSEQ));
			ret = B_FALSE;
		}
	}

	return (ret);
}

static boolean_t
mbrtoc8_null(void)
{
	char8_t out = 0x23, exp = 0x23;
	size_t len;
	mbstate_t mbs = { 0 };
	boolean_t ret = B_TRUE;

	len = mbrtoc8(&out, NULL, 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc8 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc8 incorrectly wrote to char8_t value with "
		    "null string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc8_zero(void)
{
	char8_t out, exp = '\0';
	size_t len;
	mbstate_t mbs;
	boolean_t ret = B_TRUE;

	bzero(&mbs, sizeof (mbs));
	len = mbrtoc8(&out, "", 1, &mbs);
	if (len != 0) {
		warnx("partial mbrtoc8 returned %zu, not 0", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc8 converted character to 0x%x not 0x%x",
		    out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
mbrtoc8_zero_len(void)
{
	char8_t out = 0x23, exp = 0x23;
	size_t len;
	mbstate_t mbs = { 0 };
	boolean_t ret = B_TRUE;

	len = mbrtoc8(&out, uchar_wide, 0, &mbs);
	if (len != (size_t)-2) {
		warnx("partial mbrtoc8 returned %zu, not -2", len);
		ret = B_FALSE;
	}

	if (out != exp) {
		warnx("mbrtoc8 incorrectly wrote to char8_t value with "
		    "zero length string, found 0x%x not 0x%x", out, exp);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
c8rtomb_null(void)
{
	size_t len;
	mbstate_t mbs = { 0 };
	boolean_t ret = B_TRUE;

	len = c8rtomb(NULL, 0x42, &mbs);
	if (len != 1) {
		warnx("c32rtomb returned %zu, expected %d", len, 1);
		ret = B_FALSE;
	}

	return (ret);
}


typedef boolean_t (*uchar_test_f)(void);

typedef struct uchar_test {
	uchar_test_f	ut_func;
	const char	*ut_test;
	const char	*ut_locale;
} uchar_test_t;

static const uchar_test_t uchar_tests[] = {
	{ mbrtoc32_ascii_mbstate, "mbrtoc32: ascii conversion" },
	{ mbrtoc32_ascii_internal, "mbrtoc32: ascii conversion (internal "
	    "mbstate_t)" },
	{ mbrtoc32_ascii_mbstate, "mbrtoc32: ascii conversion (C locale)",
	    "C" },
	{ mbrtoc32_ascii_internal, "mbrtoc32: ascii conversion (internal "
	    "mbstate_t) (C Locale)", "C" },
	{ mbrtoc32_badseq_utf8, "mbrtoc32: bad locale sequence (UTF-8)" },
	{ mbrtoc32_badseq_8859, "mbrtoc32: bad locale sequence (8859-1)" },
	{ mbrtoc32_roundtrip, "mbrtoc32: round trip conversion" },
	{ mbrtoc32_partial, "mbrtoc32: correctly consume partial sequences" },
	{ mbrtoc32_zero, "mbrtoc32: correctly handle L'\\0'" },
	{ mbrtoc32_zero, "mbrtoc32: correctly handle L'\\0' (C)", "C" },
	{ mbrtoc32_zero, "mbrtoc32: correctly handle L'\\0' (8859-15)",
	    "en_US.ISO8859-15" },
	{ mbrtoc32_zero_len, "mbrtoc32: correctly handle length of zero" },
	{ mbrtoc32_zero_len, "mbrtoc32: correctly handle length of zero (C)",
	    "C" },
	{ mbrtoc32_zero_len, "mbrtoc32: correctly handle length of zero "
	    "(8859-1)", "en_US.ISO8859-15" },
	{ mbrtoc32_null, "mbrtoc32: correctly handle null string" },
	{ mbrtoc32_null, "mbrtoc32: correctly handle null string (C)", "C" },
	{ mbrtoc32_null, "mbrtoc32: correctly handle null string (8859-15)",
	    "en_US.ISO8859-15" },
	{ mbrtoc32_iconv_8859, "mbrtoc32: correctly convert data from 8859-1",
	    "en_US.ISO8859-1" },
	{ mbrtoc32_iconv_euro, "mbrtoc32: correctly convert data from 8859-15",
	    "en_US.ISO8859-15" },
	{ mbrtoc16_ascii_mbstate, "mbrtoc16: ascii conversion" },
	{ mbrtoc16_ascii_internal, "mbrtoc16: ascii conversion (internal "
	    "mbstate_t)" },
	{ mbrtoc16_ascii_mbstate, "mbrtoc16: ascii conversion (C)", "C" },
	{ mbrtoc16_ascii_internal, "mbrtoc16: ascii conversion (internal "
	    "mbstate_t) (C)", "C" },
	{ mbrtoc16_null, "mbrtoc16: correctly handle null string" },
	{ mbrtoc16_null, "mbrtoc16: correctly handle null string (C)", "C" },
	{ mbrtoc16_null, "mbrtoc16: correctly handle null string (8859-15)",
	    "en_US.ISO8859-15" },
	{ mbrtoc16_zero, "mbrtoc16: correctly handle L'\\0'" },
	{ mbrtoc16_zero, "mbrtoc16: correctly handle L'\\0' (C)", "C" },
	{ mbrtoc16_zero, "mbrtoc16: correctly handle L'\\0' (8859-15)"
	    "en_US.ISO8859-15" },
	{ mbrtoc16_zero_len, "mbrtoc16: correctly handle length of zero" },
	{ mbrtoc16_zero_len, "mbrtoc16: correctly handle length of zero (C)",
	    "C" },
	{ mbrtoc16_zero_len, "mbrtoc16: correctly handle length of zero "
	    "(8859-15)", "en_US.ISO8859-15" },
	{ mbrtoc16_roundtrip, "mbrtoc16: round trip conversion" },
	{ mbrtoc16_partial, "mbrtoc16: correctly consume partial sequences" },
	{ mbrtoc16_surrogate, "mbrtoc16: correctly generate surrogate pairs "
	    "and round trip conversion" },
	{ c32rtomb_eilseq_iso8859, "c32rtomb: character outside of locale is "
	    "caught (8859-15)", "en_US.ISO8859-15" },
	{ c16rtomb_eilseq_iso8859, "c16rtomb: character outside of locale is "
	    "caught (8859-1)", "en_US.ISO8859-1" },
	{ c32rtomb_eilseq_utf8, "c32rtomb: character outside of locale is "
	    "caught (UTF-8)" },
	{ c16rtomb_bad_first, "c16rtomb: bad first surrogate pair" },
	{ c16rtomb_bad_second, "c16rtomb: bad second surrogate pair" },
	{ c32rtomb_null, "c32rtomb: correctly handle null buffer" },
	{ c32rtomb_null_euro, "c32rtomb: correctly handle null buffer "
	    "(8859-15)", "en_US.ISO8859-15" },
	{ c16rtomb_null, "c16rtomb: correctly handle null buffer" },
	{ c16rtomb_null_euro, "c16rtomb: correctly handle null buffer "
	    "(8859-15)", "en_US.ISO8859-15" },
	{ c32rtomb_iconv_ascii, "c32rtomb: correctly convert data from C",
	    "C" },
	{ c32rtomb_iconv_euro, "c32rtomb: correctly convert data from 8859-15",
	    "en_US.ISO8859-15" },
	{ mbrtoc8_roundtrip_1b, "mbrtoc8 roundtrip ascii" },
	{ mbrtoc8_roundtrip_1b, "mbrtoc8 roundtrip ascii (C)", "C" },
	{ mbrtoc8_roundtrip_1b, "mbrtoc8 roundtrip ascii (8859-1)",
	    "en_US.ISO8859-1" },
	{ mbrtoc8_roundtrip_2b, "mbrtoc8 roundtrip 2b (UTF-8)" },
	{ mbrtoc8_roundtrip_3b, "mbrtoc8 roundtrip 3b (UTF-8)" },
	{ mbrtoc8_roundtrip_4b, "mbrtoc8 roundtrip 4b (UTF-8)" },
	{ mbrtoc8_roundtrip_euro, "mbrtoc8 roundtrip conv 8859-15",
	    "en_US.ISO8859-15" },
	{ c8rtomb_bad_utf8, "invalid UTF-8 sequences" },
	/* Even if these are representable, they should still fail */
	{ c8rtomb_bad_utf8, "invalid UTF-8 sequences (C)", "C" },
	{ mbrtoc8_null, "mbrtoc8: correctly handle null string" },
	{ mbrtoc8_null, "mbrtoc8: correctly handle null string (C)", "C" },
	{ mbrtoc8_null, "mbrtoc8: correctly handle null string (8859-15)",
	    "en_US.ISO8859-15" },
	{ c8rtomb_null, "c8rtomb: correctly handle null string" },
	{ c8rtomb_null, "c8rtomb: correctly handle null string (C)", "C" },
	{ c8rtomb_null, "c8rtomb: correctly handle null string (8859-15)",
	    "en_US.ISO8859-15" },
	{ mbrtoc8_zero, "mbrtoc8: correctly handle '\\0' string" },
	{ mbrtoc8_zero, "mbrtoc8: correctly handle '\\0' string (C)", "C" },
	{ mbrtoc8_zero, "mbrtoc8: correctly handle '\\0' string (8859-15)",
	    "en_US.ISO8859-15" },

	{ mbrtoc8_zero_len, "mbrtoc8: correctly handle zero length string" },
	{ mbrtoc8_zero_len, "mbrtoc8: correctly handle zero length string (C)",
	    "C" },
	{ mbrtoc8_zero_len, "mbrtoc8: correctly handle zero length string "
	    "(8859-15)", "en_US.ISO8859-15" },
};

int
main(void)
{
	uint_t i;
	uint_t passes = 0;
	uint_t ntests = ARRAY_SIZE(uchar_tests);

	for (i = 0; i < ntests; i++) {
		boolean_t r;

		/*
		 * Default to a standard UTF-8 locale if none is requested by
		 * the test.
		 */
		if (uchar_tests[i].ut_locale != NULL) {
			update_locale(uchar_tests[i].ut_locale);
		} else {
			update_locale("en_US.UTF-8");
		}

		r = uchar_tests[i].ut_func();
		(void) fprintf(stderr, "TEST %s: %s\n", r ? "PASSED" : "FAILED",
		    uchar_tests[i].ut_test);
		if (r) {
			passes++;
		}
	}

	(void) printf("%d/%d test%s passed\n", passes, ntests,
	    passes > 1 ? "s" : "");
	return (passes == ntests ? EXIT_SUCCESS : EXIT_FAILURE);

}
