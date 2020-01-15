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
 * Copyright 2019 Joyent, Inc.
 */

#include <errno.h>
#include <libcustr.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/debug.h>

static void
expect(const char *var, custr_t *cu, const char *str, const char *file,
    size_t line)
{
	if (strcmp(custr_cstr(cu), str) == 0)
		return;

	char msgbuf[256];

	(void) snprintf(msgbuf, sizeof (msgbuf), "%s == '%s' ('%s' == '%s')",
	    var, str, custr_cstr(cu), str);

	(void) assfail(msgbuf, file, line);
}

#define	EXPECT(_cu, _str) expect(#_cu, _cu, _str, __FILE__, __LINE__)
#define	FAIL(_expr, _ev)		\
	VERIFY3S(_expr, ==, -1);	\
	VERIFY3S(errno, ==, (_ev))

int
main(void)
{
	custr_t *cu;

	VERIFY0(custr_alloc(&cu));

	VERIFY0(custr_append(cu, "12345"));
	EXPECT(cu, "12345");

	FAIL(custr_remove(cu, 6, 2), EINVAL);
	FAIL(custr_remove(cu, 2, 10), EINVAL);
	FAIL(custr_rremove(cu, 6, 2), EINVAL);
	FAIL(custr_rremove(cu, 2, 10), EINVAL);

	VERIFY0(custr_remove(cu, 0, 1));
	EXPECT(cu, "2345");
	VERIFY0(custr_rremove(cu, 1, 2));
	EXPECT(cu, "23");

	VERIFY0(custr_append(cu, "456"));
	EXPECT(cu, "23456");

	VERIFY0(custr_remove(cu, 1, 2));
	EXPECT(cu, "256");

	VERIFY0(custr_rremove(cu, 1, 2));
	EXPECT(cu, "2");

	return (0);
}
