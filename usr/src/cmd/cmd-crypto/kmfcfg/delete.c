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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <kmfapiP.h>
#include "util.h"

int
kc_delete(int argc, char *argv[])
{
	int		rv = KC_OK;
	KMF_RETURN	kmfrv = KMF_OK;
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*filename = NULL;
	char		*policyname = NULL;

	while ((opt = getopt_av(argc, argv, "i:(dbfile)p:(policy)")) != EOF) {
		switch (opt) {
			case 'i':
				filename = get_string(optarg_av, &rv);
				if (filename == NULL) {
					(void) fprintf(stderr,
					    gettext("Error dbfile input.\n"));
				}
				break;
			case 'p':
				policyname = get_string(optarg_av, &rv);
				if (policyname == NULL) {
					(void) fprintf(stderr,
					    gettext("Error policy name.\n"));
				}
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Error input option.\n"));
				rv = KC_ERR_USAGE;
				break;

		}

		if (rv != KC_OK)
			goto out;
	}

	/* No additional args allowed. */
	argc -= optind_av;
	if (argc) {
		(void) fprintf(stderr,
		    gettext("Error input option\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (filename == NULL) {
		filename = strdup(KMF_DEFAULT_POLICY_FILE);
		if (filename == NULL) {
			rv = KC_ERR_MEMORY;
			goto out;
		}
	}

	/*
	 * Must have a policy name. The policy name can not be default
	 * if using the default policy file.
	 */
	if (policyname == NULL) {
		(void) fprintf(stderr,
		    gettext("You must specify a policy name\n"));
		rv = KC_ERR_USAGE;
		goto out;
	} else if (strcmp(filename, KMF_DEFAULT_POLICY_FILE) == 0 &&
	    strcmp(policyname, KMF_DEFAULT_POLICY_NAME) == 0) {
		(void) fprintf(stderr,
		    gettext("Can not delete the default policy in the default "
		    "policy file\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	/* Check the access permission of the policy DB */
	if (access(filename, W_OK) < 0) {
		int err = errno;
		(void) fprintf(stderr,
		    gettext("Cannot access \"%s\" for delete - %s\n"),
		    filename, strerror(err));
		rv = KC_ERR_ACCESS;
		goto out;
	}

	kmfrv = kmf_delete_policy_from_db(policyname, filename);
	if (kmfrv != KMF_OK)
		rv = KC_ERR_DELETE_POLICY;

out:
	if (filename != NULL)
		free(filename);

	if (policyname != NULL)
		free(policyname);

	return (rv);
}
