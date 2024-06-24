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
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Test program for libsec:acl_totext
 */

#include <sys/types.h>
#include <sys/acl.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

extern char *acl_strerror(int);
extern acl_t acl_canned;

int
main(int argc, char **argv)
{
	acl_t	*aclp = &acl_canned;
	char	*str;
	char	*p;
	int flags = 0;
	int c;

	while ((c = getopt(argc, argv, "cns")) != -1) {
		switch ((char)c) {
		case 'c':
			flags |= ACL_COMPACT_FMT;
			break;
		case 'n':
			flags |= ACL_NORESOLVE;
			break;
		case 's':
			flags |= ACL_SID_FMT;
			break;

		case '?':
			fprintf(stderr, "usage: %s [-cns]\n", argv[0]);
			break;
		}
	}

	str = acl_totext(aclp, flags);
	if (str == NULL) {
		fprintf(stderr, "acl_totext returned NULL\n");
		return (1);
	}

	/*
	 * These are hard to read as one line, so let's
	 * convert all the commas to newlines.
	 */
	for (p = str; *p != '\0'; p++) {
		if (*p == ',')
			*p = '\n';
	}

	printf("%s\n", str);
	free(str);

	return (0);
}
