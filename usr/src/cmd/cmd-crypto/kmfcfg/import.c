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
#include <locale.h>
#include <errno.h>

#include <kmfapiP.h>

#include "util.h"

int
kc_import(int argc, char *argv[])
{
	int rv = KC_OK;
	char *filename = NULL;
	char *infile = NULL;
	char *policyname = NULL;
	POLICY_LIST *plclist = NULL, *pnode;
	int	opt, found = 0;
	extern int	optind_av;
	extern char	*optarg_av;

	while ((opt = getopt_av(argc, argv,
	    "d:(dbfile)p:(policy)i:(infile)")) != EOF) {
		switch (opt) {
			case 'd':
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
			case 'i':
				infile = get_string(optarg_av, &rv);
				if (infile == NULL) {
					(void) fprintf(stderr,
					    gettext("Error infile input.\n"));
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

	if (policyname == NULL) {
		(void) fprintf(stderr,
		    gettext("You must specify a policy name\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (infile == NULL) {
		(void) fprintf(stderr,
		    gettext("You must specify a input DB file\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	if (strcmp(filename, KMF_DEFAULT_POLICY_FILE) == 0 &&
	    strcmp(policyname, KMF_DEFAULT_POLICY_NAME) == 0) {
		(void) fprintf(stderr,
		    gettext("Can not import the default policy record to "
		    "the system default policy database\n"));
		rv = KC_ERR_USAGE;
		goto out;
	}

	rv = load_policies(infile, &plclist);
	if (rv != KMF_OK)
		goto out;

	pnode = plclist;
	while (pnode != NULL && !found) {
		if (strcmp(policyname, pnode->plc.name) == 0) {
			KMF_RETURN ret;

			found++;
			ret = kmf_verify_policy(&pnode->plc);
			if (ret != KMF_OK) {
				print_sanity_error(ret);
				rv = KC_ERR_VERIFY_POLICY;
				break;
			}
			rv = kmf_add_policy_to_db(&pnode->plc, filename,
			    B_FALSE);
		}
		pnode = pnode->next;
	}

	if (!found) {
		(void) fprintf(stderr,
		    gettext("Could not find policy \"%s\" in %s\n"),
		    policyname, infile);
		rv = KC_ERR_FIND_POLICY;
	}

out:
	if (filename != NULL)
		free(filename);

	if (policyname != NULL)
		free(policyname);

	if (infile != NULL)
		free(infile);

	free_policy_list(plclist);

	return (rv);
}
