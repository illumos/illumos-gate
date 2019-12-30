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
 * Copyright 2019 Robert Mustacchi
 */

#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <libgen.h>
#include <locale.h>
#include <libintl.h>

int
main(int argc, char *argv[])
{
	char *name;
	char uidbuf[32];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc != 1) {
		warnx(gettext("illegal arguments"));
		(void) fprintf(stderr, gettext("Usage: %s\n"),
		    basename(argv[0]));
		return (1);
	}

	/*
	 * In some cases getlogin() can fail. The most common case is due to
	 * something like using script(1). Deal with that by falling back to the
	 * current user ID, which is as accurate as we can be. This is what the
	 * ksh93 version used to do.
	 */
	name = getlogin();
	if (name == NULL) {
		uid_t uid;
		struct passwd *pass;

		uid = getuid();
		pass = getpwuid(uid);
		if (pass != NULL) {
			name = pass->pw_name;
		} else {
			(void) snprintf(uidbuf, sizeof (uidbuf), "%u", uid);
			name = uidbuf;
		}
	}

	if (printf("%s\n", name) == -1) {
		err(EXIT_FAILURE, gettext("failed to write out login name"));
	}

	return (0);
}
