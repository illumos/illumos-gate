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
 * Copyright 2018 Jason King
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/debug.h>
#include "demangle-sys.h"
#include "demangle_int.h"

#define	DEMANGLE_DEBUG	"DEMANGLE_DEBUG"

static pthread_once_t debug_once = PTHREAD_ONCE_INIT;
volatile boolean_t demangle_debug;

static sysdem_lang_t
detect_lang(const char *str)
{
	size_t n = strlen(str);

	if (n < 3 || str[0] != '_')
		return (SYSDEM_LANG_AUTO);

	switch (str[1]) {
	case 'Z':
		return (SYSDEM_LANG_CPP);

	case '_':
		break;

	default:
		return (SYSDEM_LANG_AUTO);
	}

	/* why they use ___Z sometimes is puzzling... *sigh* */
	if (str[2] == '_' && str[3] == 'Z')
		return (SYSDEM_LANG_CPP);

	return (SYSDEM_LANG_AUTO);
}

static void
check_debug(void)
{
	if (getenv(DEMANGLE_DEBUG))
		demangle_debug = B_TRUE;
}

char *
sysdemangle(const char *str, sysdem_lang_t lang, sysdem_ops_t *ops)
{
	VERIFY0(pthread_once(&debug_once, check_debug));

	if (ops == NULL)
		ops = sysdem_ops_default;

	if (lang == SYSDEM_LANG_AUTO) {
		lang = detect_lang(str);
		if (lang == SYSDEM_LANG_AUTO) {
			errno = ENOTSUP;
			return (NULL);
		}
	}

	switch (lang) {
	case SYSDEM_LANG_AUTO:
		break;
	case SYSDEM_LANG_CPP:
		return (cpp_demangle(str, ops));
	}

	errno = ENOTSUP;
	return (NULL);
}
