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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Recover metadevice configurations that have been lost by scanning
 * media, intelligent guessing, or other means.
 */

#include <meta.h>
#include <sdssc.h>

/*
 * print usage message
 */
static void
usage(
	mdsetname_t	*sp,
	int		eval
)
{
	(void) fprintf(stderr, gettext(
	    "usage: %s [-s setname] [-v] raw-device -p\n"), myname);
	(void) fprintf(stderr, gettext(
	    "       %s [-s setname] [-v] [-n] raw-device -p -d\n"), myname);
	(void) fprintf(stderr, gettext(
	    "       %s [-s setname] [-v] [-n] raw-device -p -m\n"), myname);

	md_exit(sp, eval);
}

int
main(
	int	argc,
	char	*argv[]
)
{
	char		*sname = MD_LOCAL_NAME;
	mdcmdopts_t	options = (MDCMD_DOIT | MDCMD_PRINT);

	mdsetname_t	*sp = NULL;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	mdname_t	*namep;
	char		*devname;
	int		error;
	int		c;

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

	if (sdssc_bind_library() == SDSSC_ERROR) {
		(void) printf(gettext(
		    "%s: Interface error with libsds_sc.so\n"), argv[0]);
		exit(1);
	}

	if (md_init(argc, argv, 0, 1, ep) != 0 ||
	    meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit((mdsetname_t *)NULL, 1);
	}

	/* parse arguments */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:hnv?")) != -1) {
		switch (c) {
		case 's':
			sname = optarg;
			break;

		case 'h':
			usage(sp, 0);
			break;

		case 'v':
			options |= MDCMD_VERBOSE;
			break;

		case 'n':
			options &= ~MDCMD_DOIT;
			break;

		case '?':
			if (optopt == '?')
				usage(sp, 0);
			/*FALLTHROUGH*/
		default:
			usage(sp, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	/* sname is MD_LOCAL_NAME if not specified on the command line */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((argc == 0) || (argv[0] == NULL)) {
		usage(sp, 1);
	}

	/* get raw device name */
	devname = Strdup(argv[0]);
	argv++;
	argc--;

	if ((namep = metaname(&sp, devname, UNKNOWN, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* check for a valid component */
	if ((metagetsize(namep, ep) == MD_DISKADDR_ERROR)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* check for ownership */
	assert(sp != NULL);
	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/*
	 * If the component is not a metadevice and we have a named set
	 * make sure that the component is part of the named set.
	 */
	if (strcmp(sp->setname, MD_LOCAL_NAME) != 0) {
		if (!metaismeta(namep)) {
			if (! meta_is_drive_in_thisset(sp, namep->drivenamep,
			    FALSE, ep)) {
				(void) mddeverror(ep, MDE_NOT_IN_SET,
				    namep->dev, namep->cname);
				mde_perror(ep, "");
				md_exit(sp, 1);
			}
		}
	}

	/* parse command line -- currently only soft partitions are supported */
	if ((argc > 0) && (*argv != NULL) && strncmp(*argv, "-p", 2) == 0) {
		error = meta_recover_sp(sp, namep, --argc, ++argv, options, ep);
	} else {
		usage(sp, 1);
	}

	if (error < 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	} else {
		if (meta_update_md_cf(sp, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
