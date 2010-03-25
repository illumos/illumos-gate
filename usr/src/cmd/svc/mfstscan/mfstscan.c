/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <libuutil.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest_find.h"
#include "manifest_hash.h"

#define	MAX_DEPTH	24

/*
 * mfstscan - service manifest change detection utility
 *
 * mfstscan walks the given filesystem hierarchies, and reports those manifests
 * with changed or absent hash entries.  Manifests are expected to end with a
 * .xml suffix--other files will be ignored.
 */

static void
usage()
{
	(void) fprintf(stderr, gettext("Usage: %s [-t] path ...\n"),
	    uu_getpname());
	exit(UU_EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	manifest_info_t **entry;
	manifest_info_t **manifests;
	int i;
	int paths_walked = 0;
	struct stat sb;
	int status;
	int tflag = 0;

	(void) uu_setpname(argv[0]);

	while ((i = getopt(argc, argv, "t")) != -1) {
		switch (i) {
		case 't':
			tflag = 1;
			paths_walked = 1;
			break;
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	if (optind >= argc)
		usage();

	for (i = optind; i < argc; i++) {
		if (tflag) {
			char *pname = mhash_filename_to_propname(argv[i],
			    B_FALSE);

			if (pname != NULL)
				(void) puts(pname);
			else
				uu_warn(gettext("cannot resolve pathname "
				    "for %s"), argv[i]);

			continue;
		}

		if (stat(argv[i], &sb) == -1) {
			uu_warn(gettext("cannot stat %s"), argv[i]);
			continue;
		}

		status = find_manifests(argv[i], &manifests,
		    CHECKHASH|CHECKEXT);
		if (status < 0) {
			uu_warn(gettext("file tree walk of %s encountered "
			    "error.  %s\n"), argv[i], strerror(errno));
		} else {
			paths_walked++;
			if (manifests != NULL) {
				for (entry = manifests;
				    *entry != NULL;
				    entry++) {
					(void) printf("%s\n",
					    (*entry)->mi_path);
				}
				free_manifest_array(manifests);
			}
		}

	}

	if (!paths_walked)
		uu_die(gettext("no paths walked\n"));

	return (0);
}
