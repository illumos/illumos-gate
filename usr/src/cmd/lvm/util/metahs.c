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
 * hotspare maintenance
 */

#include <meta.h>
#include <sdssc.h>

/*
 * possible actions
 */
enum metahs_op {
	NONE,
	ADD_A_HS,
	DELETE_A_HS,
	ENABLE_A_HS,
	REPLACE_A_HS,
	STATUS_A_HSP
};

/*
 * report status of a hotspare pool
 */
static int
status_hsp(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	md_error_t	*ep
)
{
	mdprtopts_t	options = (PRINT_HEADER | PRINT_SUBDEVS | PRINT_DEVID);
	mdnamelist_t	*nlp = NULL;

	/* must have set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* print status */
	if (meta_hsp_print(sp, hspnp, &nlp, NULL, stdout, options, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

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
usage:	%s [-s setname] -a hot_spare_pool [component...]\n\
	%s [-s setname] -a \"all\" component...\n\
	%s [-s setname] -d hot_spare_pool [component...]\n\
	%s [-s setname] -d \"all\" component...\n\
	%s [-s setname] -e component...\n\
	%s [-s setname] -r hot_spare_pool component_old component_new\n\
	%s [-s setname] -r \"all\" component_old component_new\n\
	%s [-s setname] -i [hot_spare_pool...]\n"),
	    myname, myname, myname, myname, myname, myname, myname, myname);
	md_exit(sp, eval);
}

/*
 * parse args and add hotspares
 */
static int
add_hotspares(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	mdnamelist_t	*nlp = NULL;
	int		cnt;
	mdhspnamelist_t	*p;
	int		rval = -1;

	/* get hotspare pool name(s) */
	if (argc < 1)
		usage(*spp, 1);
	if ((argc > 1) && meta_is_all(argv[0])) {
		/* check for ownership */
		assert(*spp != NULL);
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		if ((cnt = meta_get_hsp_names(*spp, &hspnlp, 0, ep)) < 0) {
			return (-1);
		} else if (cnt == 0) {
			return (mderror(ep, MDE_NO_HSPS, NULL));
		}
	} else { /* create the hsp nmlist from the specified hsp name */
		if (!is_hspname(argv[0]))
			return (mderror(ep, MDE_NAME_ILLEGAL, argv[0]));

		if ((cnt = metahspnamelist(spp, &hspnlp, 1, &argv[0], ep)) < 0)
			return (-1);
	}
	assert(cnt > 0);
	--argc, ++argv;

	assert(*spp != NULL);

	/* grab set lock */
	if (meta_lock(*spp, TRUE, ep))
		return (-1);

	/* check for ownership */
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	/* get hotspares */
	if (metanamelist(spp, &nlp, argc, argv,
	    LOGICAL_DEVICE, ep) < 0) {
		goto out;
	}

	/* add hotspares */
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		if (meta_hs_add(*spp, hspnp, nlp, options, ep) != 0)
			goto out;
	}
	rval = 0;

	/* cleanup, return success */
out:
	if (hspnlp != NULL)
		metafreehspnamelist(hspnlp);
	if (nlp != NULL)
		metafreenamelist(nlp);
	return (rval);
}

/*
 * parse args and delete hotspares
 */
static int
delete_hotspares(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	mdnamelist_t	*nlp = NULL;
	int		cnt;
	mdhspnamelist_t	*p;
	int		rval = -1;

	/* get hotspare pool name(s) */
	if (argc < 1)
		usage(*spp, 1);
	if ((argc > 1) && meta_is_all(argv[0])) {
		/* check for ownership */
		assert(*spp != NULL);
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		if ((cnt = meta_get_hsp_names(*spp, &hspnlp, 0, ep)) < 0) {
			return (-1);
		} else if (cnt == 0) {
			return (mderror(ep, MDE_NO_HSPS, NULL));
		}
	} else if ((cnt = metahspnamelist(spp, &hspnlp, 1, &argv[0],
	    ep)) < 0) {
		return (-1);
	}
	assert(cnt > 0);
	--argc, ++argv;

	assert(*spp != NULL);

	/* grab set lock */
	if (meta_lock(*spp, TRUE, ep))
		return (-1);

	/* check for ownership */
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	/* get hotspares */
	if (metanamelist(spp, &nlp, argc, argv,
	    LOGICAL_DEVICE, ep) < 0) {
		goto out;
	}

	/* delete hotspares */
	cnt = 0;
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		if (meta_hs_delete(*spp, hspnp, nlp, options, ep) != 0) {
			if (mdisdeverror(ep, MDE_INVAL_HS))
				mdclrerror(ep);
			else
				goto out;
		} else {
			++cnt;
		}
	}

	/* make sure we got some */
	if ((nlp != NULL) && (cnt == 0)) {
		(void) mddeverror(ep, MDE_INVAL_HS, nlp->namep->dev,
		    nlp->namep->cname);
		goto out;
	}

	/* success */
	rval = 0;

	/* cleanup, return success */
out:
	if (hspnlp != NULL)
		metafreehspnamelist(hspnlp);
	if (nlp != NULL)
		metafreenamelist(nlp);
	return (rval);
}

/*
 * parse args and enable hotspares
 */
static int
enable_hotspares(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdnamelist_t	*nlp = NULL;
	int		rval = -1;

	/* enable hotspares */
	if (argc < 1)
		usage(*spp, 1);

	/* get list of hotspares */
	if (metanamelist(spp, &nlp, argc, argv,
	    LOGICAL_DEVICE, ep) < 0)
		goto out;
	assert(nlp != NULL);

	assert(*spp != NULL);

	/* grab set lock */
	if (meta_lock(*spp, TRUE, ep))
		return (-1);

	/* check for ownership */
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	/* enable hotspares */
	rval = meta_hs_enable(*spp, nlp, options, ep);

	/* cleanup, return success */
out:
	metafreenamelist(nlp);
	return (rval);
}

/*
 * parse args and replace hotspares
 */
static int
replace_hotspares(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	int		cnt;
	mdname_t	*oldnp;
	mdname_t	*newnp;
	mdhspnamelist_t	*p;
	int		rval = -1;

	/* get hotspare pool name(s) */
	if (argc != 3)
		usage(*spp, 1);
	if (meta_is_all(argv[0])) {
		/* check for ownership */
		assert(*spp != NULL);
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		if ((cnt = meta_get_hsp_names(*spp, &hspnlp, 0, ep)) < 0) {
			return (-1);
		} else if (cnt == 0) {
			return (mderror(ep, MDE_NO_HSPS, NULL));
		}
	} else if ((cnt = metahspnamelist(spp, &hspnlp, 1, &argv[0],
	    ep)) < 0) {
		return (-1);
	}
	assert(cnt > 0);

	assert(*spp != NULL);

	/* grab set lock */
	if (meta_lock(*spp, TRUE, ep))
		return (-1);

	/* check for ownership */
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	/* get old component */
	if ((oldnp = metaname(spp, argv[1], LOGICAL_DEVICE, ep)) == NULL)
		goto out;

	/* get new component */
	if ((newnp = metaname(spp, argv[2], LOGICAL_DEVICE, ep)) == NULL)
		goto out;

	/* replace hotspares */
	cnt = 0;
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		if (meta_hs_replace(*spp, hspnp, oldnp, newnp, options, ep)
		    != 0) {
			if (mdisdeverror(ep, MDE_INVAL_HS))
				mdclrerror(ep);
			else
				goto out;
		} else {
			++cnt;
		}
	}

	/* make sure we got some */
	if (cnt == 0) {
		(void) mddeverror(ep, MDE_INVAL_HS, oldnp->dev, oldnp->cname);
		goto out;
	}

	/* success */
	rval = 0;

	/* cleanup, return success */
out:
	if (hspnlp != NULL)
		metafreehspnamelist(hspnlp);
	return (rval);
}

/*
 * print_hsp_devid will collect the information for each underlying
 * physical device for all the hotspare pools and print out the
 * device relocation information
 * INPUT:
 *	mdsetname_t *sp			set the hsp is in
 *	mdhspnamelist_t *hspnlp		list of hsp
 *	FILE	*fp			where to print to
 *	md_error_t	*ep		errors
 * RETURN:
 *	0 	SUCCESS
 *	-1	ERROR
 */
static int
print_hsp_devid(
	mdsetname_t	*sp,
	mdhspnamelist_t *hspnlp,
	FILE		*fp,
	md_error_t	*ep
)
{
	mddevid_t	*ldevidp = NULL;
	int		retval = 0;
	mdhspnamelist_t	*p;
	mddevid_t	*nextp;

	/* for all hotspare pools */
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;
		uint_t		hsi;

		/* for all hotspares within a pool */
		for (hsi = 0;
		    hsi < hspnp->unitp->hotspares.hotspares_len; hsi++) {
			mdname_t	*hsname;

			hsname =
			    hspnp->unitp->hotspares.hotspares_val[hsi].hsnamep;

			meta_create_non_dup_list(hsname, &ldevidp);
		}
	}

	retval = meta_print_devid(sp, fp, ldevidp, ep);

	/* cleanup */
	for (nextp = ldevidp; nextp != NULL; ldevidp = nextp) {
		Free(ldevidp->ctdname);
		nextp = ldevidp->next;
		Free(ldevidp);
	}
	return (retval);
}

/*
 * parse args and status hotspares
 */
static int
status_hotspares(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	int		cnt;
	mdhspnamelist_t	*p;
	int		rval = -1;

	/* get hotspare pool name(s) */
	if (argc == 0) {
		/* check for ownership */
		assert(*spp != NULL);
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		if ((cnt = meta_get_hsp_names(*spp, &hspnlp, 0, ep)) < 0) {
			return (-1);
		} else if (cnt == 0) {
			return (mderror(ep, MDE_NO_HSPS, NULL));
		}
	} else if ((cnt = metahspnamelist(spp, &hspnlp, argc, argv, ep)) < 0) {
		return (-1);
	}
	assert(cnt > 0);

	/* check for ownership */
	assert(*spp != NULL);
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	/* status hotspare pools */
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		if (status_hsp(*spp, hspnp, ep) != 0)
			goto out;
	}

	if (print_hsp_devid(*spp, hspnlp, stdout, ep) == 0) {
		rval = 0;
	}

	/* cleanup, return success */
out:
	if (hspnlp != NULL)
		metafreehspnamelist(hspnlp);
	return (rval);
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
	char		*sname = MD_LOCAL_NAME;
	mdsetname_t	*sp = NULL;
	enum metahs_op	which_op = NONE;
	mdcmdopts_t	options = (MDCMD_PRINT | MDCMD_DOIT);
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
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hs:aderin?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			break;

		case 'a':
			if (which_op != NONE)
				usage(sp, 1);
			which_op = ADD_A_HS;
			break;

		case 'd':
			if (which_op != NONE)
				usage(sp, 1);
			which_op = DELETE_A_HS;
			break;

		case 'e':
			if (which_op != NONE)
				usage(sp, 1);
			which_op = ENABLE_A_HS;
			break;

		case 'r':
			if (which_op != NONE)
				usage(sp, 1);
			which_op = REPLACE_A_HS;
			break;

		case 'i':
			if (which_op != NONE)
				usage(sp, 1);
			which_op = STATUS_A_HSP;
			break;

		case 'n':
			if (called_thru_rpc == TRUE) {
				options &= ~MDCMD_DOIT;
			} else {
				usage(sp, 1);
			}
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

	/* get set context */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/*
	 * Send the command to all nodes if the -s argument refers to a MN
	 * set or the next argument refers to MN set hotspare name ( argc
	 * greater than optind if there is a next argument)
	 */
	if ((called_thru_rpc == FALSE) &&
	    (meta_is_mn_set(sp, ep) || ((argc > optind) &&
	    meta_is_mn_name(&sp, argv[optind], ep)))) {
		int	i;
		int	newargc;
		int	result;
		char	**newargv;

		/*
		 * If we are dealing with a MN set and we were not
		 * called thru an rpc call, we are just to send this
		 * command string to the master of the set and let it
		 * deal with it.
		 * First we send out a dryrun version of this command.
		 * If that returns success, we know it succeeded on all
		 * nodes and it is safe to do the real command now.
		 */
		newargv = calloc(argc+1, sizeof (char *));
		newargv[0] = "metahs";
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
		 * MD_DRYRUN from the flags. If this fails the master must panic
		 * as the mddbs may be inconsistent.
		 */
		newargv[1] = ""; /* this was "-n" before */
		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_RETRY_BUSY | MD_PANIC_WHEN_INCONSISTENT,
		    NO_CONTEXT_STRING, ep);
		free(newargv);

		/* No further action required */
		md_exit(sp, result);
	}

	argc -= optind;
	argv += optind;
	if (which_op == NONE)
		usage(sp, 1);

	/*
	 * if a hot spare pool was specified by name then
	 * get the canonical form of the name and set up
	 * sp if the name was specified in the form 'set/hsp'
	 * unless 'all' is specified or the request is made to
	 * enable a hs which means that argv[0] will be a component
	 */
	if (argc > 0 && !meta_is_all(argv[0]) && which_op != ENABLE_A_HS) {
		char *cname = NULL;

		cname = meta_name_getname(&sp, argv[0], HSP_DEVICE, ep);
		if (cname == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		Free(cname);
	}

	if (which_op == STATUS_A_HSP) {
		if (status_hotspares(&sp, argc, argv, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		md_exit(sp, 0);
	}

	if (meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}


	/* dispatch */
	switch (which_op) {

	case ADD_A_HS:
		if (add_hotspares(&sp, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		break;

	case DELETE_A_HS:
		if (delete_hotspares(&sp, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		break;

	case ENABLE_A_HS:
		if (enable_hotspares(&sp, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		break;

	case REPLACE_A_HS:
		if (replace_hotspares(&sp, argc, argv, options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		break;

	default:
		assert(0);
		break;
	}

	/* update md.cf */
out:
	if (meta_update_md_cf(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
