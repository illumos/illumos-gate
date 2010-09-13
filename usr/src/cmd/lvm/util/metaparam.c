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
 * change metadevice parameters
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
usage:	%s [-s setname] [options] concat/stripe | RAID\n\
	%s [-s setname] [options] mirror\n\
\n\
Concat/Stripe or RAID options:\n\
-h	hotspare_pool | \"none\"\n\
\n\
Mirror options:\n\
-r	roundrobin | geometric | first\n\
-w	parallel | serial\n\
-p	0-%d\n"), myname, myname, MD_PASS_MAX);

	md_exit(sp, eval);
}

/*
 * do mirror parameters
 */
static int
mirror_params(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	int		argc,
	char		*argv[],
	md_error_t	*ep
)
{
	mm_params_t	mmp;
	int		modified = 0;
	int		c;

	/* we must have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* initialize */
	(void) memset(&mmp, '\0', sizeof (mmp));

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:r:w:p:")) != -1) {
		switch (c) {
		case 's':
			break;

		case 'r':
			if (name_to_rd_opt(mirnp->cname, optarg,
			    &mmp.read_option, ep) != 0) {
				return (-1);
			}
			mmp.change_read_option = 1;
			modified = 1;
			break;

		case 'w':
			if (name_to_wr_opt(mirnp->cname, optarg,
			    &mmp.write_option, ep) != 0) {
				return (-1);
			}
			mmp.change_write_option = 1;
			modified = 1;
			break;

		case 'p':
			if (name_to_pass_num(mirnp->cname, optarg,
			    &mmp.pass_num, ep) != 0) {
				return (-1);
			}
			mmp.change_pass_num = 1;
			modified = 1;
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

	/* if just printing */
	if (! modified) {
		if (meta_mirror_get_params(sp, mirnp, &mmp, ep) != 0)
			return (-1);
		(void) printf(
		    gettext(
		    "%s: Mirror current parameters are:\n"),
		    mirnp->cname);
		if (meta_print_mirror_options(mmp.read_option,
		    mmp.write_option, mmp.pass_num, 0, NULL,
		    sp, stdout, ep) != 0) {
			return (-1);
		}
	}

	/* otherwise, change parameters */
	else {
		if (meta_mirror_set_params(sp, mirnp, &mmp, ep) != 0)
			return (-1);

		/* update md.cf */
		if (meta_update_md_cf(sp, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * do stripe parameters
 */
static int
stripe_params(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	int		argc,
	char		*argv[],
	md_error_t	*ep
)
{
	ms_params_t	msp;
	int		modified = 0;
	mdhspname_t	*hspnp;
	int		c;

	/* we must have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	/* initialize */
	(void) memset(&msp, '\0', sizeof (msp));

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:h:")) != -1) {
		switch (c) {
		case 's':
			break;

		case 'h':
			if (meta_is_none(optarg)) {
				msp.hsp_id = MD_HSP_NONE;
			} else if ((hspnp = metahspname(&sp, optarg,
			    ep)) == NULL) {
				return (-1);
			} else if (metachkhsp(sp, hspnp, ep) != 0) {
				return (-1);
			} else {
				msp.hsp_id = hspnp->hsp;
			}
			msp.change_hsp_id = 1;
			modified = 1;
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

	/* if just printing */
	if (! modified) {
		if (meta_stripe_get_params(sp, stripenp, &msp, ep) != 0)
			return (-1);
		if (msp.hsp_id == MD_HSP_NONE)
			hspnp = NULL;
		else if ((hspnp = metahsphspname(&sp, msp.hsp_id, ep)) == NULL)
			return (-1);
		(void) printf(gettext(
		    "%s: Concat/Stripe current parameters are:\n"),
		    stripenp->cname);
		if (meta_print_stripe_options(hspnp, NULL, stdout, ep) != 0)
			return (-1);
	}

	/* otherwise, change parameters */
	else {
		if (meta_stripe_set_params(sp, stripenp, &msp, ep) != 0)
			return (-1);

		/* update md.cf */
		if (meta_update_md_cf(sp, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * do raid parameters
 */
static int
raid_params(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	int		argc,
	char		*argv[],
	md_error_t	*ep
)
{
	mr_params_t	msp;
	int		modified = 0;
	mdhspname_t	*hspnp;
	int		c;

	/* we must have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* initialize */
	(void) memset(&msp, '\0', sizeof (msp));

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:h:")) != -1) {
		switch (c) {
		case 's':
			break;

		case 'h':
			if (meta_is_none(optarg)) {
				msp.hsp_id = MD_HSP_NONE;
			} else if ((hspnp = metahspname(&sp, optarg,
			    ep)) == NULL) {
				return (-1);
			} else if (metachkhsp(sp, hspnp, ep) != 0) {
				return (-1);
			} else {
				msp.hsp_id = hspnp->hsp;
			}
			msp.change_hsp_id = 1;
			modified = 1;
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

	/* if just printing */
	if (! modified) {
		if (meta_raid_get_params(sp, raidnp, &msp, ep) != 0)
			return (-1);
		if (msp.hsp_id == MD_HSP_NONE)
			hspnp = NULL;
		else if ((hspnp = metahsphspname(&sp, msp.hsp_id, ep)) == NULL)
			return (-1);
		(void) printf(gettext(
		    "%s: RAID current parameters are:\n"),
		    raidnp->cname);
		if (meta_print_raid_options(hspnp, NULL, stdout, ep) != 0)
			return (-1);
	}

	/* otherwise, change parameters */
	else {
		if (meta_raid_set_params(sp, raidnp, &msp, ep) != 0)
			return (-1);

		/* update md.cf */
		if (meta_update_md_cf(sp, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * parse args and doit
 */
int
main(
	int		argc,
	char		**argv
)
{
	char		*sname = NULL;
	mdsetname_t	*sp = NULL;
	mdname_t	*np;
	char		*miscname;
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		error;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	char		*firstarg = NULL;


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
	while ((c = getopt(argc, argv, "s:h:p:r:w:o:?")) != -1) {
		switch (c) {
		case 's':
			sname = optarg;
			break;
		case 'h':
			firstarg = optarg;
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
	if (firstarg == NULL)
		firstarg = argv[optind];
	if ((called_thru_rpc == FALSE) &&
	    meta_is_mn_name(&sp, firstarg, ep)) {
		/*
		 * If we are dealing with a MN set and we were not
		 * called thru an rpc call, we are just to send this
		 * command string to the master of the set and let it
		 * deal with it.
		 * Note that if sp is NULL, meta_is_mn_name() derives sp
		 * from firstarg which is the metadevice arg
		 * If this fails, the master must panic as the mddb may be
		 * inconsistent
		 */
		int result;
		result = meta_mn_send_command(sp, argc, argv, MD_DISP_STDERR |
		    MD_PANIC_WHEN_INCONSISTENT, NO_CONTEXT_STRING, ep);
		/* No further action required */
		md_exit(sp, result);
	}

	if ((np = metaname(&sp, argv[optind], META_DEVICE, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	assert(sp != NULL);
	/* grab set lock */
	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	if ((miscname = metagetmiscname(np, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* dispatch based on device type */
	if (strcmp(miscname, MD_STRIPE) == 0) {
		if (stripe_params(sp, np, argc, argv, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else 	if (strcmp(miscname, MD_MIRROR) == 0) {
		if (mirror_params(sp, np, argc, argv, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else 	if (strcmp(miscname, MD_RAID) == 0) {
		if (raid_params(sp, np, argc, argv, ep) != 0) {
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
