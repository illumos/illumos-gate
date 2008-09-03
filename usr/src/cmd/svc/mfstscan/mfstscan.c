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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>

#include <ftw.h>
#include <libintl.h>
#include <libscf.h>
#include <libuutil.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "manifest_hash.h"

#define	MAX_DEPTH	24

static scf_handle_t *hndl;
static int tflag;

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

/*ARGSUSED*/
static int
process(const char *fn, const struct stat *sp, int ftw_type,
    struct FTW *ftws)
{
	char *suffix_match;

	if (ftw_type != FTW_F)
		return (0);

	suffix_match = strstr(fn, ".xml");
	if (suffix_match == NULL || strcmp(suffix_match, ".xml") != 0)
		return (0);

	if (mhash_test_file(hndl, fn, 0, NULL, NULL) == MHASH_NEWFILE)
		(void) printf("%s\n", fn);

	return (0);
}

int
main(int argc, char *argv[])
{
	int i;
	int paths_walked = 0;
	struct stat sb;

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

	hndl = scf_handle_create(SCF_VERSION);

	if (scf_handle_bind(hndl) != SCF_SUCCESS)
		uu_die(gettext("cannot bind to repository: %s\n"),
		    scf_strerror(scf_error()));

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

		if (nftw(argv[i], process, MAX_DEPTH, FTW_MOUNT) == -1)
			uu_warn(gettext("file tree walk of %s encountered "
			    "error"), argv[i]);
		else
			paths_walked++;
	}

	(void) scf_handle_unbind(hndl);
	(void) scf_handle_destroy(hndl);

	if (!paths_walked)
		uu_die(gettext("no paths walked\n"));

	return (0);
}
