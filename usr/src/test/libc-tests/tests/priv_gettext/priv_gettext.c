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
#include <stdlib.h>
#include <priv.h>

/*
 * This tests priv_gettext(). The priv_gettext() function always falls back to
 * the C locale if it can't find anything. To deal with that, we've defined a
 * dummy translation for the zz_AA.UTF-8 locale which has a translation for the
 * 'dtrace_kernel' privilege.
 *
 * Normally 'dtrace_kernel' has the following description:
 *
 *   Allows DTrace kernel-level tracing.
 *
 * In the zz_AA.UTF-8 locale it has the following description:
 *
 *   Ah Elbereth Gilthoniel
 *
 * We explicitly verify that things respect the global locale and per-thread
 * locale.
 */

static const char *def = "Allows DTrace kernel-level tracing.\n";
static const char *trans = "Ah Elbereth Gilthoniel\n";

static void
priv_verify(const char *exp)
{
	char *res = priv_gettext("dtrace_kernel");
	assert(res != NULL);
	assert(strcmp(res, exp) == 0);
	free(res);
}

int
main(void)
{
	locale_t loc;

	(void) setlocale(LC_ALL, "C");
	priv_verify(def);

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	priv_verify(trans);

	(void) setlocale(LC_ALL, "C");
	loc = newlocale(LC_MESSAGES_MASK, "zz_AA.UTF-8", NULL);
	assert(loc != NULL);
	priv_verify(def);

	(void) uselocale(loc);
	priv_verify(trans);

	(void) uselocale(LC_GLOBAL_LOCALE);
	priv_verify(def);
	freelocale(loc);

	(void) setlocale(LC_ALL, "zz_AA.UTF-8");
	loc = newlocale(LC_MESSAGES_MASK, "C", NULL);
	assert(loc != NULL);
	priv_verify(trans);

	(void) uselocale(loc);
	priv_verify(def);

	(void) uselocale(LC_GLOBAL_LOCALE);
	priv_verify(trans);
	freelocale(loc);

	return (0);
}
