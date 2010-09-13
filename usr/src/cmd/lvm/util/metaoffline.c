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
 * offline sub-mirror
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
usage:	%s [-s setname] [-f] mirror submirror\n"),
	    myname);
	md_exit(sp, eval);
}

/*
 * Metaoffline: to offline a metadevice
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	char		*sname = NULL;
	mdsetname_t	*sp = NULL;
	mdcmdopts_t	options = (MDCMD_PRINT);
	mdname_t	*mirnp;
	mdname_t	*submirnp;
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		error;
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

	/* parse args */
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

		case 'f':
			options |= MDCMD_FORCE;
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
	if (argc != 2)
		usage(sp, 1);

	if (sname != NULL) {
		if ((sp = metasetname(sname, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/* get names */
	if (((mirnp = metaname(&sp, argv[0], META_DEVICE, ep)) == NULL) ||
	    ((submirnp = metaname(&sp, argv[1], META_DEVICE, ep)) == NULL)) {
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
		 * If this fails, the master must panic as the mddb may be
		 * inconsistent.
		 */
		int  result;
		result = meta_mn_send_command(sp, origargc, origargv,
		    MD_DISP_STDERR | MD_PANIC_WHEN_INCONSISTENT,
		    NO_CONTEXT_STRING, ep);
		md_exit(sp, result);
	}

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

	/* offline submirror */
	if (meta_mirror_offline(sp, mirnp, submirnp, options, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* return success */
	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
