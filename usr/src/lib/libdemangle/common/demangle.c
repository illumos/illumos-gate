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
 * Copyright 2021 Jason King
 * Copyright 2019, Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sys/ctype.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <stdarg.h>
#include "demangle-sys.h"
#include "demangle_int.h"
#include "strview.h"

#define	DEMANGLE_DEBUG	"DEMANGLE_DEBUG"

static pthread_once_t debug_once = PTHREAD_ONCE_INIT;
volatile boolean_t demangle_debug;
FILE *debugf = stderr;

static struct {
	const char	*str;
	sysdem_lang_t	lang;
} lang_tbl[] = {
	{ "auto", SYSDEM_LANG_AUTO },
	{ "c++", SYSDEM_LANG_CPP },
	{ "rust", SYSDEM_LANG_RUST },
};

static const char *
langstr(sysdem_lang_t lang)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lang_tbl); i++) {
		if (lang == lang_tbl[i].lang)
			return (lang_tbl[i].str);
	}
	return ("invalid");
}

boolean_t
sysdem_parse_lang(const char *str, sysdem_lang_t *langp)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lang_tbl); i++) {
		if (strcmp(str, lang_tbl[i].str) == 0) {
			*langp = lang_tbl[i].lang;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * A quick check if str can possibly be a mangled string. Currently, that
 * means it must start with _Z or __Z.
 */
static boolean_t
is_mangled(const char *str, size_t n)
{
	strview_t sv;

	sv_init_str(&sv, str, str + n);

	if (!sv_consume_if_c(&sv, '_'))
		return (B_FALSE);
	(void) sv_consume_if_c(&sv, '_');
	if (sv_consume_if_c(&sv, 'Z'))
		return (B_TRUE);

	return (B_FALSE);
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
	char *res = NULL;
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

	/*
	 * If we were given an explicit language to demangle, we always
	 * use that. If not, we try to demangle as rust, then c++. Any
	 * mangled C++ symbol that manages to successfully demangle as a
	 * legacy rust symbol _should_ look the same as it can really
	 * only be a very simple C++ symbol. Otherwise, the rust demangling
	 * should fail and we can try C++.
	 */
	switch (lang) {
	case SYSDEM_LANG_CPP:
		return (cpp_demangle(str, slen, ops));
	case SYSDEM_LANG_RUST:
		return (rust_demangle(str, slen, ops));
	case SYSDEM_LANG_AUTO:
		break;
	}

	/*
	 * To save us some potential work, if the symbol cannot
	 * possibly be a rust or C++ mangled name, we don't
	 * even attempt to demangle either.
	 */
	if (!is_mangled(str, slen)) {
		/*
		 * This does mean if we somehow get a string > 2GB
		 * the debugging output will be truncated, but that
		 * seems an acceptable tradeoff.
		 */
		int len = slen > INT_MAX ? INT_MAX : slen;

		DEMDEBUG("ERROR: '%.*s' cannot be a mangled string", len, str);
		errno = EINVAL;
		return (NULL);
	}

	DEMDEBUG("trying rust");
	res = rust_demangle(str, slen, ops);

	IMPLY(ret != NULL, errno == 0);
	if (res != NULL)
		return (res);

	DEMDEBUG("trying C++");
	return (cpp_demangle(str, slen, ops));
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
