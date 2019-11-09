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
 * Copyright 2020 Joyent, Inc.
 */

#include <ctype.h>
#include <demangle-sys.h>
#include <err.h>
#include <errno.h>
#include <libcustr.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#define	_(x) gettext(x)

locale_t c_locale;

static int do_symbols(sysdem_lang_t, int, char * const *);
static int do_input(sysdem_lang_t, FILE *restrict, FILE *restrict);
static int do_demangle(const char *, sysdem_lang_t, FILE *);
static void appendc(custr_t *, char);
static void xputc(int, FILE *);

static void
usage(void)
{
	(void) fprintf(stderr, _("Usage: %s [-l lang] [sym...]\n"),
	    getprogname());
	exit(2);
}

int
main(int argc, char * const *argv)
{
	sysdem_lang_t lang = SYSDEM_LANG_AUTO;
	int c;
	int ret;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * For detecting symbol boundaries, we want to use the C locale
	 * definitions for use in isalnum_l().
	 */
	if ((c_locale = newlocale(LC_CTYPE_MASK, "C", NULL)) == NULL)
		err(EXIT_FAILURE, _("failed to construct C locale"));

	while ((c = getopt(argc, argv, "hl:")) != -1) {
		switch (c) {
		case 'l':
			if (sysdem_parse_lang(optarg, &lang))
				break;

			errx(EXIT_FAILURE, _("Unsupported language '%s'\n"),
			    optarg);
		case 'h':
		case '?':
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		ret = do_symbols(lang, argc, argv);
	else
		ret = do_input(lang, stdin, stdout);

	return ((ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS);
}

static int
do_symbols(sysdem_lang_t lang, int argc, char * const *argv)
{
	int ret = 0;

	for (int i = 0; i < argc; i++) {
		if (do_demangle(argv[i], lang, stdout) < 0)
			ret = -1;
		else
			xputc('\n', stdout);
	}

	return (ret);
}

static int
do_input(sysdem_lang_t lang, FILE *restrict in, FILE *restrict out)
{
	custr_t *word = NULL;
	int c;
	int ret = 0;
	boolean_t in_symbol = B_FALSE;

	if (custr_alloc(&word) != 0)
		err(EXIT_FAILURE, _("failed to allocate memory"));

	while ((c = fgetc(in)) != EOF) {
		if (in_symbol) {
			/*
			 * All currently supported mangling formats only use
			 * alphanumeric characters, '.', '_', or '$' in
			 * mangled names. Once we've seen the potential start
			 * of a symbol ('_'), we accumulate subsequent
			 * charaters into 'word'. If we encounter a character
			 * that is not a part of that set ([A-Za-z0-9._$]), we
			 * treat it as a delimiter, we stop accumulating
			 * characters into word, and we attempt to demangle the
			 * accumulated string in 'word' by calling
			 * demangle_custr().
			 *
			 * Similar utilities like c++filt behave in a similar
			 * fashion when reading from stdin to allow for
			 * demangling of symbols embedded in surrounding text.
			 */
			if (isalnum_l(c, c_locale) || c == '.' || c == '_' ||
			    c == '$') {
				appendc(word, c);
				continue;
			}

			/*
			 * Hit a symbol boundary, attempt to demangle what
			 * we've accumulated in word and reset word.
			 */
			if (do_demangle(custr_cstr(word), lang, out) < 0)
				ret = -1;

			custr_reset(word);
			in_symbol = B_FALSE;
		}

		if (c != '_') {
			xputc(c, out);
		} else {
			in_symbol = B_TRUE;
			appendc(word, c);
		}
	}

	if (ferror(in))
		err(EXIT_FAILURE, _("error reading input"));

	/*
	 * If we were accumulating characters for a symbol and hit EOF,
	 * attempt to demangle what we accumulated.
	 */
	if (custr_len(word) > 0 && do_demangle(custr_cstr(word), lang, out) < 0)
		ret = -1;

	custr_free(word);
	return (ret);
}

/*
 * Attempt to demangle 'sym' as a symbol for 'lang' and write the result
 * to 'out'. If 'sym' could not be demangled as 'lang' symbol, the original
 * string is output instead.
 *
 * If an error other than 'not a mangled symbol' is encountered (e.g. ENOMEM),
 * a warning is sent to stderr and -1 is returned. Otherwise, 0 is returned
 * (including when 'sym' is merely not a mangled symbol of 'lang').
 */
static int
do_demangle(const char *sym, sysdem_lang_t lang, FILE *out)
{
	char *demangled = sysdemangle(sym, lang, NULL);

	if (demangled == NULL && errno != EINVAL) {
		warn(_("error while demangling '%s'"), sym);
		return (-1);
	}

	if (fprintf(out, "%s", (demangled != NULL) ? demangled : sym) < 0)
		err(EXIT_FAILURE, _("failed to write to output"));

	free(demangled);
	return (0);
}

static void
appendc(custr_t *cus, char c)
{
	if (custr_appendc(cus, c) == 0)
		return;
	err(EXIT_FAILURE, _("failed to save character from input"));
}

static void
xputc(int c, FILE *out)
{
	if (fputc(c, out) < 0)
		err(EXIT_FAILURE, _("failed to write output"));
}
