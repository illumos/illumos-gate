/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <string.h>
#include <libzfs.h>
#include <errno.h>

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: fstype [-v] <device>\n"));
	exit(1);
}

static void
dump_nvlist(nvlist_t *list, int indent)
{
	nvpair_t *elem = NULL;

	while ((elem = nvlist_next_nvpair(list, elem)) != NULL) {
		switch (nvpair_type(elem)) {
		case DATA_TYPE_STRING:
			{
				char *value;

				verify(nvpair_value_string(elem, &value) == 0);
				(void) printf("%*s%s='%s'\n", indent, "",
				    nvpair_name(elem), value);
			}
			break;

		case DATA_TYPE_UINT64:
			{
				uint64_t value;

				verify(nvpair_value_uint64(elem, &value) == 0);
				(void) printf("%*s%s=%llu\n", indent, "",
				    nvpair_name(elem), (u_longlong_t)value);
			}
			break;

		case DATA_TYPE_NVLIST:
			{
				nvlist_t *value;

				verify(nvpair_value_nvlist(elem, &value) == 0);
				(void) printf("%*s%s\n", indent, "",
				    nvpair_name(elem));
				dump_nvlist(value, indent + 4);
			}
			break;

		case DATA_TYPE_NVLIST_ARRAY:
			{
				nvlist_t **value;
				uint_t c, count;

				verify(nvpair_value_nvlist_array(elem, &value,
				    &count) == 0);

				for (c = 0; c < count; c++) {
					(void) printf("%*s%s[%u]\n", indent, "",
					    nvpair_name(elem), c);
					dump_nvlist(value[c], indent + 8);
				}
			}
			break;

		default:

			(void) printf("bad config type %d for %s\n",
			    nvpair_type(elem), nvpair_name(elem));
		}
	}
}

int
main(int argc, char **argv)
{
	int c, fd;
	int verbose = 0;
	nvlist_t *config;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		usage();

	if ((fd = open64(argv[0], O_RDONLY)) < 0) {
		perror("open64");
		return (1);
	}

	if ((config = zpool_read_label(fd)) == NULL)
		return (1);

	(void) printf("zfs\n");

	if (verbose)
		dump_nvlist(config, 4);

	(void) close(fd);

	return (0);
}
