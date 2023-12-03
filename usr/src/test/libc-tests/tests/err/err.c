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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * This file exercises the various err(3C)/warn(3C) functions and produces
 * output that is checked by the corresponding err.ksh script.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <sys/debug.h>

static FILE *stream = stderr;

typedef enum variant {
	VARIANT_ = 0,	/* warn(), err() */
	VARIANT_C,	/* warnc(), errc() */
	VARIANT_X,	/* warnx(), errx() */
	VARIANT_V,	/* vwarn(), verr() */
	VARIANT_VC,	/* vwarnc(), verrc() */
	VARIANT_VX,	/* vwarnx(), verrx() */
} variant_t;

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: err [-e errno] [-x code] [-v variant]\n");
	exit(EXIT_FAILURE);
}

void
callback_func(int code)
{
	(void) fprintf(stream, "CALLBACK %d\n", code);
}

void
xtest(variant_t variant, int errcode, int exitcode, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);

	switch (variant) {
	case VARIANT_V:
		errno = errcode;
		if (exitcode != 0)
			verr(exitcode, fmt, va);
		else
			vwarn(fmt, va);
		break;
	case VARIANT_VC:
		errno = 0;
		if (exitcode != 0)
			verrc(exitcode, errcode, fmt, va);
		else
			vwarnc(errcode, fmt, va);
		break;
	case VARIANT_VX:
		if (exitcode != 0)
			verrx(exitcode, fmt, va);
		else
			vwarnx(fmt, va);
		break;
	default:
		errx(EXIT_FAILURE, "Unhandled variant in %s", __func__);
	}

	va_end(va);
}

int
main(int argc, char **argv)
{
	int errcode = 0;
	int exitcode = 0;
	variant_t variant = VARIANT_;
	const char *errstr;
	long long num;
	int ch;

	/*
	 * -e	specify errno for the test
	 * -v	select variant to test
	 * -x	specify exit code for the test
	 */
	while ((ch = getopt(argc, argv, "e:v:x:")) != -1) {
		switch (ch) {
		case 'e':
			num = strtonum(optarg, 0, 127, &errstr);
			if (errstr != NULL)
				errx(EXIT_FAILURE, "-x: %s", errstr);
			errcode = (int)num;
			break;
		case 'v':
			num = strtonum(optarg, 0, VARIANT_VX, &errstr);
			if (errstr != NULL)
				errx(EXIT_FAILURE, "-v: %s", errstr);
			switch (num) {
			case VARIANT_:
				variant = VARIANT_;
				break;
			case VARIANT_C:
				variant = VARIANT_C;
				break;
			case VARIANT_X:
				variant = VARIANT_X;
				break;
			case VARIANT_V:
				variant = VARIANT_V;
				break;
			case VARIANT_VC:
				variant = VARIANT_VC;
				break;
			case VARIANT_VX:
				variant = VARIANT_VX;
				break;
			default:
				errx(EXIT_FAILURE, "Unknown variant %lld", num);
			}
			break;
		case 'x':
			num = strtonum(optarg, 0, 127, &errstr);
			if (errstr != NULL)
				errx(EXIT_FAILURE, "-x: %s", errstr);
			exitcode = (int)num;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		errx(EXIT_FAILURE, "Unexpected argument '%s'.", argv[1]);

	switch (variant) {
	case VARIANT_:
		errno = errcode;
		if (exitcode != 0)
			err(exitcode, "E/%d/%d", variant, exitcode);
		else
			warn("W/%d", variant);
		break;
	case VARIANT_C:
		errno = 0;
		if (exitcode != 0)
			errc(exitcode, errcode, "E/%d/%d", variant, exitcode);
		else
			warnc(errcode, "W/%d", variant);
		break;
	case VARIANT_X:
		if (exitcode != 0)
			errx(exitcode, "E/%d/%d", variant, exitcode);
		else
			warnx("W/%d", variant);
		break;
	case VARIANT_V:
	case VARIANT_VC:
	case VARIANT_VX:
		if (exitcode != 0) {
			xtest(variant, errcode, exitcode, "E/%d/%d", variant,
			    exitcode);
		} else {
			xtest(variant, errcode, exitcode, "W/%d", variant);
		}
		break;
	}

	return (0);
}
