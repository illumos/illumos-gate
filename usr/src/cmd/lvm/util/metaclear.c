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
 * clear metadevices
 */

#include <meta.h>
#include <sdssc.h>


/*
 * clear metadevice or hotspare pool
 */
static int
clear_name(
	mdsetname_t	**spp,
	char		*uname,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{

	/* clear hotspare pool */
	if (is_existing_hsp(*spp, uname)) {
		mdhspname_t	*hspnp;

		/* get hotspare pool name */
		if ((hspnp = metahspname(spp, uname, ep)) == NULL)
			return (-1);
		assert(*spp != NULL);

		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep))
			return (-1);

		/* check for ownership */
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		/* clear hotspare pool */
		return (meta_hsp_reset(*spp, hspnp, options, ep));
	}

	/* clear metadevice */
	else {
		mdname_t	*np;

		/* check for ownership */
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		/* get metadevice name */
		if (((np = metaname(spp, uname, META_DEVICE, ep)) == NULL) ||
		    (metachkmeta(np, ep) != 0)) {
			return (-1);
		}
		assert(*spp != NULL);

		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep))
			return (-1);

		/* clear metadevice */
		return (meta_reset_by_name(*spp, np, options, ep));
	}
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
usage:	%s [-s setname] -a\n\
	%s [-s setname] [options] metadevice...\n\
options:\n\
-f	force clear\n\
-r	recursive clear\n\
-p	clear all soft partitions on metadevice/component\n"), myname, myname);
	md_exit(sp, eval);
}

/*
 * mainline.   crack command line arguments.
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	char		*sname = MD_LOCAL_NAME;
	mdsetname_t	*sp = NULL;
	int		aflag = 0;
	int		pflag = 0;
	int		set_flag = 0;
	mdcmdopts_t	options = (MDCMD_PRINT|MDCMD_DOIT);
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		eval = 1;
	int		error;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	int		mnset = FALSE;

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
			meta_check_root(ep) != 0)
		goto errout;

	/* parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hs:afrp?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			set_flag++;
			break;

		case 'a':
			++aflag;
			options |= MDCMD_FORCE;
			break;

		case 'f':
			options |= MDCMD_FORCE;
			break;

		case 'r':
			options |= MDCMD_RECURSE | MDCMD_FORCE;
			break;
		case 'p':
			++pflag;
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

	/* with mn sets if -a, set name must have been specified by -s */
	if (called_thru_rpc && aflag && !set_flag) {
		md_eprintf(gettext(
		    "-a parameter requires the use of -s in multi-node sets"));
		md_exit(sp, 1);
	}

	/* get set context */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (called_thru_rpc) {
		/* Check if the device is open  on all nodes */
		options |= MDCMD_MN_OPEN_CHECK;
	}

	if (aflag) {	/* clear all devices */
		if (argc != 0)
			usage(sp, 1);

		/*
		 * If a MN set, we will generate a series of individual
		 * metaclear commands which will each grab the set lock.
		 * Therefore do not grab the set lock now.
		 */

		if (!meta_is_mn_set(sp, ep)) {
			/* grab set lock */
			if (meta_lock(sp, TRUE, ep))
				goto errout;

			/* check for ownership */
			if (meta_check_ownership(sp, ep) != 0)
				goto errout;
		} else {
			mnset = TRUE;
		}

		/* reset all devices in set */
		if (meta_reset_all(sp, options, ep) != 0) {
			if (!mnset)
				mde_perror(ep, "");
		} else
			eval = 0;
	} else {
		/*
		 * We are dealing with either a single or multiple names.
		 * The set for the command is either denoted by the -s option
		 * or the set of the first name.
		 */
		if (argc <= 0)
			usage(sp, 1);

		if (meta_is_mn_name(&sp, argv[0], ep))
			mnset = TRUE;
		eval = 0;

		for (; (argc > 0); --argc, ++argv) {
			char		*cname;

			/*
			 * If we are dealing with a MN set and we were not
			 * called thru an rpc call, we are just to send this
			 * command string to the master of the set and let it
			 * deal with it.
			 */
			if (!called_thru_rpc && mnset) {
				/* get the canonical name */
				if (pflag) {
					/*
					 * If -p, set cname to the device
					 * argument.
					 */
					cname = Strdup(argv[0]);
				} else {
					/*
					 * For hotspares and metadevices, set
					 * cname to the full name,
					 * setname/hspxxx or setname/dxxx
					 */
					cname = meta_name_getname(&sp,
					    argv[0], META_DEVICE, ep);
					if (cname == NULL) {
						mde_perror(ep, "");
						eval = 1;
						continue;
					}
				}
				if (meta_mn_send_metaclear_command(sp,
				    cname, options, pflag, ep) != 0) {
					eval = 1;
				}
				Free(cname);
			} else {
				if (pflag) {
					/*
					 * clear all soft partitions on named
					 * devices
					 */
					if (meta_sp_reset_component(sp, argv[0],
					    options, ep) != 0) {
						mde_perror(ep, "");
						eval = 1;
						continue;
					}
				} else {
					/*
					 * get the canonical name and
					 * setup sp if it has been
					 * specified as part of the
					 * metadevice/hsp name param
					 */
					cname = meta_name_getname(&sp,
					    argv[0], META_DEVICE, ep);
					if (cname == NULL) {
						mde_perror(ep, "");
						eval = 1;
						continue;
					}

					/* clear named devices */
					if (clear_name(&sp, cname,
					    options, ep) != 0) {
						mde_perror(ep, "");
						eval = 1;
						Free(cname);
						continue;
					}
					Free(cname);
				}
			}
		}
	}
	/* update md.cf */
	if (meta_update_md_cf(sp, ep) != 0) {
		mde_perror(ep, "");
		eval = 1;
	}
	md_exit(sp, eval);

errout:
	mde_perror(ep, "");
	md_exit(sp, eval);
	/*NOTREACHED*/
	return (eval);
}
