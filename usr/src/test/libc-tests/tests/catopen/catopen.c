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
#include <nl_types.h>
#include <sys/types.h>

/*
 * This is designed to check that we properly are honoring the global and
 * per-thread locale when opening up a message catalog. To do this, we use the
 * "TEST" message catalog which only exists in the system in the C/POSIX
 * locales and thus alternate with our test locale zz_AA.UTF-8 which should not
 * have it.
 */

#define	INVALID_CAT	((nl_catd)-1)

static void
catopen_verify(boolean_t find)
{
	nl_catd cat;

	cat = catopen("TEST", NL_CAT_LOCALE);
	if (find == B_TRUE) {
		assert(cat != INVALID_CAT);
		(void) catclose(cat);
	} else {
		assert(cat == INVALID_CAT);
	}
}

int
main(void)
{
	locale_t loc;

	(void) setlocale(LC_ALL, "C");
	catopen_verify(B_TRUE);

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	catopen_verify(B_FALSE);

	(void) setlocale(LC_MESSAGES, "C");
	catopen_verify(B_TRUE);

	(void) setlocale(LC_ALL, "C");
	loc = newlocale(LC_MESSAGES_MASK, "zz_AA.UTF-8", NULL);
	assert(loc != NULL);

	catopen_verify(B_TRUE);
	(void) uselocale(loc);
	catopen_verify(B_FALSE);

	(void) uselocale(LC_GLOBAL_LOCALE);
	catopen_verify(B_TRUE);
	freelocale(loc);

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	catopen_verify(B_FALSE);

	loc = newlocale(LC_MESSAGES_MASK, "C", NULL);
	assert(loc != NULL);

	catopen_verify(B_FALSE);
	(void) uselocale(loc);
	catopen_verify(B_TRUE);

	return (0);
}
