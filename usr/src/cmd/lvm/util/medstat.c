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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mediator status utility.
 */

#include <meta.h>
#include <sdssc.h>

static void
usage(
	mdsetname_t	*sp,
	char		*string)
{
	if ((string != NULL) && (*string != '\0'))
		md_eprintf("%s\n", string);
	(void) fprintf(stderr, gettext(
	    "usage:	%s [-q] -s setname\n"),
	myname);
	md_exit(sp, (string == NULL) ? 0 : 1);
}

/*
 * parse args and do it
 */
int
main(
	int			argc,
	char			*argv[]
)
{
	int			c;
	char			*sname = MD_LOCAL_NAME;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	mdsetname_t		*sp = NULL;
	md_set_desc		*sd;
	int			i;
	int			max_meds;
	md_h_t			mdh;
	med_data_t		medd;
	int			medok = 0;
	int			golden = 0;
	int			verbose = 1;
	int			error;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((sdssc_bind_library() == SDSSC_OKAY) &&
		(sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
		    &error) == SDSSC_PROXY_DONE))
			exit(error);

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "qs:?")) != -1) {
		switch (c) {
		    case 'q':
			    verbose = 0;
			    break;
		    case 's':
			    sname = optarg;
			    break;
		    case '?':
			    if (optopt == '?')
				    usage(sp, NULL);
			    /*FALLTHROUGH*/
		    default:
			usage(sp, gettext("unknown command"));
		}
	}

	/* must have set for everything else */
	if (strcmp(sname, MD_LOCAL_NAME) == 0)
		usage(sp, gettext("setname must be specified"));

	/* snarf MDDB */
	if (meta_setup_db_locations(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (sd->sd_med.n_cnt == 0) {
		if (verbose)
			(void) printf(gettext(
			    "No mediator hosts configured for set \"%s\".\n"),
			    sname);
		md_exit(sp, 2);
	}

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	if (verbose)
		(void) printf("%8.8s\t\t%6.6s\t%6.6s\n",
		    gettext("Mediator"), gettext("Status"),
		    gettext("Golden"));

	for (i = 0; i < max_meds; i++) {

		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;

		(void) memset(&medd, '\0', sizeof (medd));
		(void) memset(&mdh, '\0', sizeof (mdh));
		mdh = sd->sd_med.n_lst[i];	/* structure assignment */

		if (verbose)
			(void) printf("%-17.17s\t",
			    sd->sd_med.n_lst[i].a_nm[0]);

		if (clnt_med_get_data(&mdh, sp, &medd, ep) == -1) {
			if (mdanyrpcerror(ep)) {
				if (verbose)
					(void) printf("%s\n",
					    gettext("Unreachable"));
				continue;
			} else if (mdiserror(ep, MDE_MED_ERROR)) {
				if (verbose)
					(void) printf("%s\n",
					    gettext("Bad"));
			} else {
				if (verbose)
					(void) printf("%s\n",
					    gettext("Fatal"));
			}
			mde_perror(ep, "");
			if (mdiserror(ep, MDE_MED_ERROR))
				continue;
			md_exit(sp, 1);
		}

		if (verbose)
			(void) printf("%s", gettext("Ok"));

		if (medd.med_dat_fl & MED_DFL_GOLDEN) {
			if (verbose)
				(void) printf("\t%s",
				    gettext("Yes"));
			golden++;
		} else {
			if (verbose)
				(void) printf("\t%s",
				    gettext("No"));
		}

		if (verbose)
			(void) printf("\n");

		medok++;
	}

	if (golden)
		md_exit(sp, 0);

	if (medok < ((sd->sd_med.n_cnt / 2) + 1))
		md_exit(sp, 1);

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
