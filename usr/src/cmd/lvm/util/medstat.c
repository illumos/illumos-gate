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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
	int			verbose = 1;

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

	/*
	 * There is no need to proxy the command to owner of the set
	 * to get the mediator information as the /etc/lvm/meddb file
	 * contains the required information and so it can be used.
	 */
	if ((sdssc_bind_library() == SDSSC_ERROR))  {
		(void) fprintf(stderr,
		    "Failed to initialised libscsds.so.1\n");
		exit(1);
	}


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

	/*
	 * Get the mediator information from file
	 * /etc/lvm/meddb and print it.
	 */

	if (meta_mediator_info_from_file(sname, verbose, ep)) {
		md_exit(sp, 1);
	}

	md_exit(sp, 0);
	/* NOTREACHED */
	return (0);
}
