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
 * Copyright 2020 Robert Mustacchi
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

static const char *uchar_wide = "光";
static const char32_t uchar_value = 0x5149;
static const char *uchar_hello = "hello";

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
		warnx("got bad char32_t, expected 0x%x, found 0x%x\n", 'h',
		    out);
		ret = B_FALSE;
	}

	if ((len = mbrtoc32(&out, uchar_hello + 1, 4, mbs)) != 1) {
		warnx("expected mbrtoc32 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'e') {
		warnx("got bad char32_t, expected 0x%x, found 0x%x\n", 'h',
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
		warnx("found bad errno, expected %d, found %d\n", errno,
		    EILSEQ);
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
		warnx("found bad errno, expected %d, found %d\n", errno,
		    EILSEQ);
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
		warnx("got bad char16_t, expected 0x%x, found 0x%x\n", 'h',
		    out);
		ret = B_FALSE;
	}

	if ((len = mbrtoc16(&out, uchar_hello + 1, 4, mbs)) != 1) {
		warnx("expected mbrtoc16 to return 1, returned %zu", len);
		ret = B_FALSE;
	}

	if (out != 'e') {
		warnx("got bad char16_t, expected 0x%x, found 0x%x\n", 'h',
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
		warnx("c32rtomb returned %zd, expected -1\n", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("expected errno set to %d was %d", EILSEQ, errno);
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
		warnx("c32rtomb returned %zd, expected -1\n", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("expected errno set to %d was %d", EILSEQ, errno);
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
		warnx("c32rtomb returned %zd, expected -1\n", len);
		ret = B_FALSE;
	}

	if (errno != EILSEQ) {
		warnx("expected errno set to %d was %d", EILSEQ, errno);
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
			warnx("c16rtomb returned %zd, expected 0\n", len);
			ret = B_FALSE;
		}

		len = c16rtomb(buf, bad[i], &mbs);
		if (len != (size_t)-1) {
			warnx("c16rtomb surrogate %x returned %zd, expected "
			    "-1\n", bad[i], len);
			ret = B_FALSE;
		}

		if (errno != EILSEQ) {
			warnx("expected errno set to %d was %d", EILSEQ, errno);
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
			warnx("c16rtomb surrogate %x returned %zd, expected "
			    "-1\n", bad[i], len);
			ret = B_FALSE;
		}

		if (errno != EILSEQ) {
			warnx("expected errno set to %d was %d", EILSEQ, errno);
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
	{ mbrtoc32_badseq_utf8, "mbrtoc32: bad locale sequence (UTF-8)" },
	{ mbrtoc32_roundtrip, "mbrtoc32: round trip conversion" },
	{ mbrtoc32_partial, "mbrtoc32: correctly consume partial sequences" },
	{ mbrtoc32_zero, "mbrtoc32: correctly handle L'\\0'" },
	{ mbrtoc32_zero_len, "mbrtoc32: correctly handle length of zero" },
	{ mbrtoc32_null, "mbrtoc32: correctly handle null string" },
	{ mbrtoc16_ascii_mbstate, "mbrtoc16: ascii conversion" },
	{ mbrtoc16_ascii_internal, "mbrtoc16: ascii conversion (internal "
	    "mbstate_t)" },
	{ mbrtoc16_null, "mbrtoc16: correctly handle null string" },
	{ mbrtoc16_zero, "mbrtoc16: correctly handle L'\\0'" },
	{ mbrtoc16_zero_len, "mbrtoc16: correctly handle length of zero" },
	{ mbrtoc16_roundtrip, "mbrtoc16: round trip conversion" },
	{ mbrtoc16_partial, "mbrtoc16: correctly consume partial sequences" },
	{ mbrtoc16_surrogate, "mbrtoc16: correctly generate surrogate pairs "
	    "and round trip conversion" },
	{ c32rtomb_eilseq_iso8859, "c32rtomb: character outside of locale is "
	    "caught", "en_US.ISO8859-1" },
	{ c16rtomb_eilseq_iso8859, "c16rtomb: character outside of locale is "
	    "caught", "en_US.ISO8859-1" },
	{ c32rtomb_eilseq_utf8, "c32rtomb: character outside of locale is "
	    "caught" },
	{ c16rtomb_bad_first, "c16rtomb: bad first surrogate pair" },
	{ c16rtomb_bad_second, "c16rtomb: bad second surrogate pair" },
	{ c32rtomb_null, "c32rtomb: correctly handle null buffer" },
	{ c16rtomb_null, "c16rtomb: correctly handle null buffer" },
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
