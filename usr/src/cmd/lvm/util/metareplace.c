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
 * replace mirror component
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
usage:	%s [-s setname] mirror component-old component-new\n\
	%s [-s setname] -e mirror component\n\
	%s [-s setname] [-f] RAID component-old component-new\n\
	%s [-s setname] [-f] -e RAID component\n"),
	    myname, myname, myname, myname);
	md_exit(sp, eval);
}

/*
 * online replace a physical disk in a metamirror
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
	mdname_t	*namep;
	int		eflag = 0;
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		error;
	char		*uname = NULL;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	int		origargc = argc;
	char		**origargv = argv;

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

	/* parse arguments */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hs:efn?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			break;

		case 'e':
			++eflag;
			break;

		case 'f':
			options |= MDCMD_FORCE;
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
	argc -= optind;
	argv += optind;

	if (sname != NULL) {
		if ((sp = metasetname(sname, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/* get device */
	if (argc < 1)
		usage(sp, 1);

	uname = argv[0];

	if (((namep = metaname(&sp, uname, META_DEVICE, ep)) == NULL)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (metachkmeta(namep, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	assert(sp != NULL);
	if ((called_thru_rpc == FALSE) &&
	    meta_is_mn_name(&sp, argv[0], ep)) {
		/*
		 * If we are dealing with a MN set and we were not
		 * called thru an rpc call, we are just to send this
		 * command string to the master of the set and let it
		 * deal with it.
		 * Note that if sp is NULL, meta_is_mn_name() derives sp
		 * from argv[0] which is the metadevice arg
		 */
		int  i;
		int  newargc;
		int  result;
		char *miscname;
		char **newargv;

		if ((miscname = metagetmiscname(namep, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		newargv = calloc(origargc+1, sizeof (char *));
		newargv[0] = "metareplace";
		newargv[1] = "-n"; /* always do "-n" first */
		newargc = 2;
		for (i = 1; i < origargc; i++, newargc++) {
			newargv[newargc] = origargv[i];
		}

		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_DRYRUN, NO_CONTEXT_STRING, ep);

		/* If we've found a problem don't do it for real */
		if (result != 0) {
			md_exit(sp, result);
		}
		/*
		 * Do it for real now. Remove "-n" from the arguments and
		 * MD_DRYRUN from the flags. If this fails, the master must
		 * panic as the mddbs may be inconsistent.
		 */
		newargv[1] = ""; /* this was "-n" before */
		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_RETRY_BUSY | MD_PANIC_WHEN_INCONSISTENT,
		    NO_CONTEXT_STRING, ep);

		free(newargv);

		/*
		 * if the metareplace command succeeds for a mirror, send a
		 * resync starting message for the metadevice
		 */
		if ((result == 0) && (strcmp(miscname, MD_MIRROR) == 0)) {
			if ((result = meta_mn_send_resync_starting(namep, ep))
			    != 0)
				mde_perror(ep, "Unable to start resync");
		}
		md_exit(sp, result);
	}

	--argc, ++argv;

	/* grab set lock */
	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* check for ownership */
	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (eflag) {				/* enable component */
		mdname_t	*compnp;

		if (argc != 1)
			usage(sp, 1);

		if ((compnp = metaname(&sp, argv[0], UNKNOWN, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		if (meta_enable_byname(sp, namep, compnp, options, ep)
		    != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	} else {				/* replace component */
		mdname_t	*oldnp;
		mdname_t	*newnp;

		if (argc != 2)
			usage(sp, 1);

		if ((oldnp = metaname(&sp, argv[0], UNKNOWN, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		if ((newnp = metaname(&sp, argv[1], UNKNOWN, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		if (meta_replace_byname(sp, namep, oldnp, newnp,
		    options, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/* update md.cf */
	if (meta_update_md_cf(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
