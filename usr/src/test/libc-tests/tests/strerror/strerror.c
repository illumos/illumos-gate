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
 */

#include <string.h>
#include <locale.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

/*
 * This is designed to test strerorr and strerror_l's ability to react properly
 * to being in various locales. This also serves as a regression test for
 * illumos#6133.
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

static int err = ENOENT;
static const char *en = "No such file or directory";
static const char *trans = "It's a trap!";

static void
strerror_verify(const char *exp)
{
	const char *r;
	errno = 0;
	r = strerror(err);
	assert(errno == 0);
	assert(strcmp(r, exp) == 0);
}

static void
strerror_l_verify(locale_t loc, const char *exp)
{
	const char *r;
	errno = 0;
	r = strerror_l(err, loc);
	assert(errno == 0);
	assert(strcmp(r, exp) == 0);
}

int
main(void)
{
	locale_t loc;

	(void) setlocale(LC_ALL, "C");
	strerror_verify(en);

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	strerror_verify(trans);

	(void) setlocale(LC_MESSAGES, "C");
	strerror_verify(en);

	(void) setlocale(LC_ALL, "C");
	loc = newlocale(LC_MESSAGES_MASK, "zz_AA.UTF-8", NULL);
	assert(loc != NULL);

	strerror_verify(en);
	strerror_l_verify(NULL, en);
	strerror_l_verify(loc, trans);

	(void) uselocale(loc);
	strerror_verify(trans);
	strerror_l_verify(NULL, trans);
	strerror_l_verify(loc, trans);

	(void) uselocale(LC_GLOBAL_LOCALE);
	strerror_verify(en);
	strerror_l_verify(NULL, en);
	strerror_l_verify(loc, trans);

	freelocale(loc);
	return (0);
}
