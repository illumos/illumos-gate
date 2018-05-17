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
 * Copyright 2018 Nexenta Systems, Inc.
 */

/*
 * Note that this file is easiest edited with a UTF-8 capable editor,
 * as there are embedded UTF-8 symbols in some of the strings.
 */

#include <err.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

struct {
	const char *locale;
	const char *convspec;
	const float fp;
	const char *expected;
} fpconv[] = {
	"C", "%a", 3.2, "0x1.99999a0000000p+1",
	"C", "%e", 3.2, "3.200000e+00",
	"C", "%f", 3.2, "3.200000",
	"C", "%g", 3.2, "3.2",
	"ar_AE.UTF-8", "%a", 3.2, "0x1٫99999a0000000p+1",
	"ar_AE.UTF-8", "%e", 3.2, "3٫200000e+00",
	"ar_AE.UTF-8", "%f", 3.2, "3٫200000",
	"ar_AE.UTF-8", "%g", 3.2, "3٫2",
	"en_US.UTF-8", "%a", 3.2, "0x1.99999a0000000p+1",
	"en_US.UTF-8", "%e", 3.2, "3.200000e+00",
	"en_US.UTF-8", "%f", 3.2, "3.200000",
	"en_US.UTF-8", "%g", 3.2, "3.2",
	"ru_RU.UTF-8", "%a", 3.2, "0x1,99999a0000000p+1",
	"ru_RU.UTF-8", "%e", 3.2, "3,200000e+00",
	"ru_RU.UTF-8", "%f", 3.2, "3,200000",
	"ru_RU.UTF-8", "%g", 3.2, "3,2",
	NULL, NULL, 0, NULL
};

int
main(void)
{
	char buf[100];
	int i;

	for (i = 0; fpconv[i].locale != NULL; i++) {
		if (setlocale(LC_ALL, fpconv[i].locale) == NULL)
			err(1, "failed to set locale to %s", fpconv[i].locale);

		(void) sprintf(buf, fpconv[i].convspec, fpconv[i].fp);
		if (strcmp(fpconv[i].expected, buf) != 0) {
			errx(1, "locale=%s, convspec=%s, expected=%s, got=%s",
			    fpconv[i].locale, fpconv[i].convspec,
			    fpconv[i].expected, buf);
		}
	}

	return (0);
}
