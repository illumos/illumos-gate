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
 * Copyright 2019, Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ctype.h>
#include <sys/debug.h>
#include <stdarg.h>
#include "demangle-sys.h"
#include "demangle_int.h"

#define	DEMANGLE_DEBUG	"DEMANGLE_DEBUG"

static pthread_once_t debug_once = PTHREAD_ONCE_INIT;
volatile boolean_t demangle_debug;
FILE *debugf = stderr;

static const char *
langstr(sysdem_lang_t lang)
{
	switch (lang) {
	case SYSDEM_LANG_AUTO:
		return ("auto");
	case SYSDEM_LANG_CPP:
		return ("c++");
	case SYSDEM_LANG_RUST:
		return ("rust");
	default:
		return ("invalid");
	}
}

static sysdem_lang_t
detect_lang(const char *str, size_t n)
{
	const char *p = str;
	size_t len;

	if (n < 3 || str[0] != '_')
		return (SYSDEM_LANG_AUTO);

	/*
	 * Check for ^_Z or ^__Z
	 */
	p = str + 1;
	if (*p == '_') {
		p++;
	}

	if (*p != 'Z')
		return (SYSDEM_LANG_AUTO);

	/*
	 * Sadly, rust currently uses the same prefix as C++, however
	 * demangling rust as a C++ mangled name yields less than desirable
	 * results.  However rust names end with a hash.  We use that to
	 * attempt to disambiguate
	 */

	/* Find 'h'<hexdigit>+E$ */
	if ((p = strrchr(p, 'h')) == NULL)
		return (SYSDEM_LANG_CPP);

	if ((len = strspn(p + 1, "0123456789abcdef")) == 0)
		return (SYSDEM_LANG_CPP);

	p += len + 1;

	if (p[0] != 'E' || p[1] != '\0')
		return (SYSDEM_LANG_CPP);

	return (SYSDEM_LANG_RUST);
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
	/*
	 * While the language specific demangler code can handle non-NUL
	 * terminated strings, we currently don't expose this to consumers.
	 * Consumers should still pass in a NUL-terminated string.
	 */
	size_t slen;

	VERIFY0(pthread_once(&debug_once, check_debug));

	DEMDEBUG("name = '%s'", (str == NULL) ? "(NULL)" : str);
	DEMDEBUG("lang = %s (%d)", langstr(lang), lang);

	if (str == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	slen = strlen(str);

	switch (lang) {
		case SYSDEM_LANG_AUTO:
		case SYSDEM_LANG_CPP:
		case SYSDEM_LANG_RUST:
			break;
		default:
			errno = EINVAL;
			return (NULL);
	}

	if (ops == NULL)
		ops = sysdem_ops_default;

	if (lang == SYSDEM_LANG_AUTO) {
		lang = detect_lang(str, slen);
		if (lang != SYSDEM_LANG_AUTO)
			DEMDEBUG("detected language is %s", langstr(lang));
	}

	switch (lang) {
	case SYSDEM_LANG_CPP:
		return (cpp_demangle(str, slen, ops));
	case SYSDEM_LANG_RUST:
		return (rust_demangle(str, slen, ops));
	case SYSDEM_LANG_AUTO:
		DEMDEBUG("could not detect language");
		errno = ENOTSUP;
		return (NULL);
	default:
		/*
		 * This can't happen unless there's a bug with detect_lang,
		 * but gcc doesn't know that.
		 */
		errno = EINVAL;
		return (NULL);
	}
}

int
demdebug(const char *fmt, ...)
{
	va_list ap;

	flockfile(debugf);
	(void) fprintf(debugf, "LIBDEMANGLE: ");
	va_start(ap, fmt);
	(void) vfprintf(debugf, fmt, ap);
	(void) fputc('\n', debugf);
	(void) fflush(debugf);
	va_end(ap);
	funlockfile(debugf);

	return (0);
}
