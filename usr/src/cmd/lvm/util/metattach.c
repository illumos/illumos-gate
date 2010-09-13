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
 * attach submirrors
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
usage:	%s [-s setname] mirror [metadevice]\n\
	%s [-s setname] [-i interlace] concat/stripe component...\n\
	%s [-s setname] RAID component...\n\
	%s [-s setname] [-A alignment] softpart size|all\n"),
	    myname, myname, myname, myname);
	md_exit(sp, eval);
}

/*
 * attach more space to a soft partition
 */
static int
sp_attach(
	mdsetname_t	**spp,
	mdname_t	*spnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	int		c;
	sp_ext_offset_t	alignment = 0;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "ns:A:")) != -1) {
		switch (c) {
		case 'n':
		case 's':
			break;
		case 'A':
			if (meta_sp_parsesize(optarg, &alignment) == -1) {
			    usage(*spp, 1);
			    /* NOTREACHED */
			}
			break;
		default:
			usage(*spp, 1);
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind + 1;
	argv += optind + 1;

	if (argc != 1)
		usage(*spp, 1);

	if (meta_sp_attach(*spp, spnp, argv[0], options, alignment, ep) != 0) {
		return (-1);
	}

	/* update md.cf file */
	if (meta_update_md_cf(*spp, ep) != 0)
		return (-1);

	return (0);
}
/*
 * attach components to stripe
 */
static int
stripe_attach(
	mdsetname_t	**spp,
	mdname_t	*stripenp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	diskaddr_t	interlace = 0;
	int		c;
	mdnamelist_t	*compnlp = NULL;
	mdnamelist_t	*p;
	mdname_t	*currootnp;
	md_stripe_t	*stripep;
	md_row_t	*rp;
	md_comp_t	*cp;


	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:ani:")) != -1) {
		switch (c) {
		case 'n':
		case 's':
			break;

		case 'a':
			break;	/* obsolete */

		case 'i':
			if (parse_interlace(stripenp->cname, optarg,
			    &interlace, ep) != 0) {
				return (-1);
			}
			if (meta_stripe_check_interlace(interlace,
			    stripenp->cname, ep))
				return (-1);
			break;

		default:
			usage(*spp, 1);
			/*NOTREACHED*/
			break;
		}
	}

	argc -= optind + 1;
	argv += optind + 1;

	if (argc <= 0)
		usage(*spp, 1);

	/* get list of components */
	if (metanamelist(spp, &compnlp, argc, argv,
	    UNKNOWN, ep) < 0)
		return (-1);
	assert(compnlp != NULL);
	for (p = compnlp; (p != NULL); p = p->next) {
		mdname_t	*compnp = p->namep;

		/* see if we are a soft partition */
		if (meta_sp_issp(*spp, compnp, ep) != 0) {
			/* nope, check component */
			if (metachkcomp(compnp, ep) != 0)
				return (-1);
		}
	}

	/* get root device */
	if ((currootnp = meta_get_current_root_dev(*spp, ep)) != NULL) {
		/*
		 * Root is either a stripe or a slice
		 * If root device is the 1st component of the stripe
		 * Then fail as root cannot be expanded
		 */
		if ((stripep = meta_get_stripe(*spp, stripenp, ep)) == NULL)
			return (-1);

		rp = &stripep->rows.rows_val[0];
		cp = &rp->comps.comps_val[0];
		if (metachkcomp(cp->compnamep, ep) == 0) {
			/* Component is a disk */
			if (strcmp(currootnp->cname,
			    cp->compnamep->cname) == 0) {
				md_eprintf(gettext(
				"%s: volume mounted as root cannot be "
				"expanded\n"), stripenp->cname);
				md_exit(*spp, 1);
			}
		}
	}

	/* attach components */
	if (meta_stripe_attach(*spp, stripenp, compnlp, interlace, options,
	    ep) != 0) {
		return (-1);
	}

	/* update md.cf file */
	if (meta_update_md_cf(*spp, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * attach components to raid
 */
static int
raid_attach(
	mdsetname_t	**spp,
	mdname_t	*raidnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	int		c;
	mdnamelist_t	*compnlp = NULL;
	mdnamelist_t	*p;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:ai:")) != -1) {
		switch (c) {
		case 'n':
		case 's':
			break;

		case 'a':
			break;	/* obsolete */

		default:
			usage(*spp, 1);
			/*NOTREACHED*/
			break;
		}
	}
	argc -= optind + 1;
	argv += optind + 1;
	if (argc <= 0)
		usage(*spp, 1);

	/* get list of components */
	if (metanamelist(spp, &compnlp, argc, argv,
	    UNKNOWN, ep) < 0)
		return (-1);
	assert(compnlp != NULL);
	for (p = compnlp; (p != NULL); p = p->next) {
		mdname_t	*compnp = p->namep;

		/* check for soft partitions */
		if (meta_sp_issp(*spp, compnp, ep) != 0) {
			/* check disk */
			if (metachkcomp(compnp, ep) != 0)
				return (-1);
		}
	}

	/* attach components */
	if (meta_raid_attach(*spp, raidnp, compnlp, options, ep) != 0)
		return (-1);

	/* update md.cf file */
	if (meta_update_md_cf(*spp, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * attach submirror to mirror
 */
static int
mirror_attach(
	mdsetname_t	**spp,
	mdname_t	*mirnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	int		c;
	mdname_t	*submirnp;

	/* reset and parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "ns:")) != -1) {
		switch (c) {
		case 'n':
		case 's':
			break;

		default:
			usage(*spp, 1);
			/*NOTREACHED*/
			break;
		}
	}
	argc -= optind + 1;
	argv += optind + 1;

	/* get submirror */
	if (argc == 1) {
		if (((submirnp = metaname(spp, argv[0], META_DEVICE,
		    ep)) == NULL) ||
		    (metachkmeta(submirnp, ep) != 0)) {
			return (-1);
		}
	} else if (argc == 0) {
		submirnp = NULL;
	} else {
		usage(*spp, 1);
	}

	/* attach submirror */
	if (meta_mirror_attach(*spp, mirnp, submirnp, options, ep) != 0)
		return (-1);

	/* update md.cf file */
	if (meta_update_md_cf(*spp, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * attach devices
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	char		*sname = NULL;
	mdsetname_t	*sp = NULL;
	mdcmdopts_t	options = (MDCMD_PRINT|MDCMD_DOIT);
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

	/* initialize */
	if ((cp = strstr(argv[0], ".rpc_call")) == NULL) {
		if (sdssc_bind_library() == SDSSC_OKAY)
			if (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
						&error) == SDSSC_PROXY_DONE)
				exit(error);
	} else {
		*cp = '\0'; /* cut off ".rpc_call" */
		called_thru_rpc = TRUE;
	}

	if (md_init(argc, argv, 0, 1, ep) != 0 ||
			meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* find set and metadevice first */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hns:A:ai:?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 'n':
			if (called_thru_rpc == TRUE) {
				options &= ~MDCMD_DOIT;
			} else {
				usage(sp, 1);
			}
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
		 */
		int	i;
		int	newargc;
		int	result;
		char	**newargv;

		if ((miscname = metagetmiscname(np, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		newargv = calloc(argc+1, sizeof (char *));
		newargv[0] = "metattach";
		newargv[1] = "-n"; /* always do "-n" first */
		newargc = 2;
		for (i = 1; i < argc; i++, newargc++)
			newargv[newargc] = argv[i];

		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_DRYRUN, NO_CONTEXT_STRING, ep);

		/* If we found a problem don't do it for real */
		if (result != 0) {
			md_exit(sp, result);
		}

		/*
		 * Do it for real now. Remove "-n" from the arguments and
		 * MD_DRYRUN from the flags. If we fail now, the master must
		 * panic as the mddbs may be inconsistent.
		 */
		newargv[1] = ""; /* this was "-n" before */
		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_RETRY_BUSY | MD_PANIC_WHEN_INCONSISTENT,
		    NO_CONTEXT_STRING, ep);

		free(newargv);

		/*
		 * If the metattach command succeeds, for a mirror, send a
		 * resync starting message for the metadevice
		 */
		if ((result == 0) && (strcmp(miscname, MD_MIRROR) == 0))
			if ((result = meta_mn_send_resync_starting(np, ep))
			    != 0)
				mde_perror(ep, "Unable to start resync");
		md_exit(sp, result);
	}

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
		if (stripe_attach(&sp, np, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else if (strcmp(miscname, MD_RAID) == 0) {
		if (raid_attach(&sp, np, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		if (mirror_attach(&sp, np, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else if (strcmp(miscname, MD_TRANS) == 0) {
		md_eprintf(gettext(MD_EOF_TRANS_MSG));
		md_exit(sp, 1);
	} else if (strcmp(miscname, MD_SP) == 0) {
		if (sp_attach(&sp, np, argc, argv, options, ep) != 0) {
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
