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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * detach submirrors
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
	(void) fprintf(stderr, gettext("\
usage:	%s [-s setname] [-f] mirror submirror\n\
	%s [-s setname] [-f] trans\n"),
	    myname, myname);
	md_exit(sp, eval);
}

/*
 * detach submirror from mirror
 */
static int
mirror_detach(
	mdsetname_t	**spp,
	mdname_t	*mirnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*submirnp;
	int		c;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:f")) != -1) {
		switch (c) {
		case 's':
			break;

		case 'f':
			options |= MDCMD_FORCE;
			break;

		default:
			usage(*spp, 1);
			/*NOTREACHED*/
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage(*spp, 1);

	/* get submirror */
	if ((submirnp = metaname(spp, argv[1], META_DEVICE, ep)) == NULL)
		return (-1);

	/* detach submirror */
	if (meta_mirror_detach(*spp, mirnp, submirnp, options, ep) != 0)
		return (-1);

	/* update md.cf */
	if (meta_update_md_cf(*spp, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * detach log from trans
 */
static int
trans_detach(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	int		delayed;
	int		c;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:f")) != -1) {
		switch (c) {
		case 's':
			break;

		case 'f':
			options |= MDCMD_FORCE;
			break;

		default:
			usage(sp, 1);
			/*NOTREACHED*/
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage(sp, 1);

	/* detach log */
	if (meta_trans_detach(sp, transnp, options, &delayed, ep) != 0)
		return (-1);

	/* update md.cf */
	if (meta_update_md_cf(sp, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * parse args and doit
 */
int
main(
	int 		argc,
	char		*argv[]
)
{
	char		*sname = NULL;
	mdsetname_t	*sp = NULL;
	mdcmdopts_t	options = (MDCMD_PRINT);
	mdname_t	*np;
	char		*miscname;
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		error;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;


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

	if ((cp = strstr(argv[0], ".rpc_call")) == NULL) {
		if (sdssc_bind_library() == SDSSC_OKAY)
			if (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
						&error) == SDSSC_PROXY_DONE)
				exit(error);
	} else {
		*cp = '\0'; /* cut off ".rpc_call" */
		called_thru_rpc = TRUE;
	}


	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0 ||
			meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* find set and metadevice first */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hs:f?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			break;

		case '?':
			if (optopt == '?')
				usage(sp, 0);
			break;
		}
	}
	if ((argc - optind) <= 0)
		usage(sp, 1);

	if (sname != NULL) {
		if ((sp = metasetname(sname, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/* Get metadevice name */
	if (((np = metaname(&sp, argv[optind], META_DEVICE, ep)) == NULL) ||
	    (metachkmeta(np, ep) != 0)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	assert(sp != NULL);

	if ((called_thru_rpc == FALSE) &&
	    meta_is_mn_name(&sp, argv[optind], ep)) {
		/*
		 * If we are dealing with a MN set and we were not
		 * called thru an rpc call, we are just to send this
		 * command string to the master of the set and let it
		 * deal with it.
		 * Note that if sp is NULL, meta_is_mn_name() derives sp
		 * from argv[optind] which is the metadevice arg
		 * If this fails, the master must panic as the mddb may be
		 * inconsistent
		 */
		int  result;
		result = meta_mn_send_command(sp, argc, argv, MD_DISP_STDERR |
		    MD_PANIC_WHEN_INCONSISTENT, NO_CONTEXT_STRING, ep);
		/*
		 * The error message has been already been displayed
		 * just exit
		 */
		md_exit(sp, result);
	}

	/* grab set lock */
	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* check ownership */
	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	if ((miscname = metagetmiscname(np, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* dispatch based on device type */
	if (strcmp(miscname, MD_MIRROR) == 0) {
		if (mirror_detach(&sp, np, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else if (strcmp(miscname, MD_TRANS) == 0) {
		if (trans_detach(sp, np, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else {
		md_eprintf(gettext(
		    "%s: invalid metadevice type %s\n"),
		    np->cname, miscname);
		md_exit(sp, 1);
	}

	/* return success */
	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
