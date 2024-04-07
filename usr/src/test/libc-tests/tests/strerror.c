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
 * Copyright 2015 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

#include <string.h>
#include <locale.h>
#include <errno.h>
#include <stdio.h>
#include <sys/debug.h>

/*
 * This is designed to test strerorr and strerror_l's ability to react properly
 * to being in various locales. This also serves as a regression test for
 * illumos#6133. This also tests that strerrordesc_np() does not translate
 * propoerly.
 *
 * For this test, we utilize the poorly named 'zz_AA.UTF_8' locale which
 * was created because it actually has a translation! It 'translates'
 * the string:
 *
 * "No such file or directory" -> "It's a trap!"
 *
 * It's otherwise a boring en_US.UTF-8 locale under the hood.
 *
 * We explicitly want to verify the following cases:
 *
 * + strerror() honors the global locale before uselocale
 * + strerror() honors the per-thread locale
 * + strerror_l() always reflects the chosen locale
 */

static int terr = ENOENT;
static const char *en = "No such file or directory";
static const char *trans = "It's a trap!";

static void
strerror_verify(const char *exp)
{
	const char *r;
	errno = 0;
	r = strerror(terr);
	VERIFY0(errno);
	VERIFY0(strcmp(r, exp));
}

static void
strerror_l_verify(locale_t loc, const char *exp)
{
	const char *r;
	errno = 0;
	r = strerror_l(terr, loc);
	VERIFY0(errno);
	VERIFY0(strcmp(r, exp));
}

static void
strerrordesc_verify(const char *exp)
{
	const char *r;
	errno = 0;
	r = strerrordesc_np(terr);
	VERIFY0(errno);
	VERIFY0(strcmp(r, exp));
}

static void
strerrorname_verify(int errnum, const char *exp)
{
	const char *r;
	errno = 0;
	r = strerrorname_np(errnum);
	VERIFY0(errno);
	VERIFY0(strcmp(r, exp));
}

int
main(void)
{
	locale_t loc;

	(void) setlocale(LC_ALL, "C");
	strerror_verify(en);
	strerrordesc_verify(en);
	strerrorname_verify(0, "0");
	strerrorname_verify(EIO, "EIO");

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	strerror_verify(trans);
	strerrordesc_verify(en);
	strerrorname_verify(ENOENT, "ENOENT");
	strerrorname_verify(ENOTSUP, "ENOTSUP");

	(void) setlocale(LC_MESSAGES, "C");
	strerror_verify(en);
	strerrordesc_verify(en);
	strerrorname_verify(EMFILE, "EMFILE");

	(void) setlocale(LC_ALL, "C");
	loc = newlocale(LC_MESSAGES_MASK, "zz_AA.UTF-8", NULL);
	VERIFY(loc != NULL);

	strerror_verify(en);
	strerror_l_verify(NULL, en);
	strerror_l_verify(loc, trans);
	strerrordesc_verify(en);
	strerrorname_verify(ENFILE, "ENFILE");

	(void) uselocale(loc);
	strerror_verify(trans);
	strerror_l_verify(NULL, trans);
	strerror_l_verify(loc, trans);
	strerrordesc_verify(en);
	strerrorname_verify(EL2HLT, "EL2HLT");

	(void) uselocale(LC_GLOBAL_LOCALE);
	strerror_verify(en);
	strerror_l_verify(NULL, en);
	strerror_l_verify(loc, trans);
	strerrordesc_verify(en);
	strerrorname_verify(ENOTSUP, "ENOTSUP");

	/*
	 * Validate a few different error cases. 135 is a Xenix special and 102
	 * is reserved. They both have an error message, but no actual constant.
	 */
	VERIFY3P(strerrordesc_np(1234567), ==, NULL);
	VERIFY3P(strerrordesc_np(102), !=, NULL);
	VERIFY3P(strerrordesc_np(135), !=, NULL);
	VERIFY3P(strerrorname_np(1234567), ==, NULL);
	VERIFY3P(strerrorname_np(102), ==, NULL);
	VERIFY3P(strerrorname_np(135), ==, NULL);

	freelocale(loc);
	return (0);
}
