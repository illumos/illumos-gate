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
 * rename or exchange metadevice identity
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
usage:	%s [-s setname] [-f] [-x] metadevice1 metadevice2\n\
	%s -h\n\
options:\n\
-s	operations are done on the set setname, rather than the local set\n\
-f	force exchange or rename\n\
-x	exchange the identities of metadevice1 and metadevice2\n\
-h	help: print this message\n"), myname, myname);
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
	char		*sname	= NULL;
	mdsetname_t	*sp	= NULL;
	int		xflag	= 0;
	mdcmdopts_t	options	= (MDCMD_PRINT | MDCMD_DOIT);
	md_error_t	status	= mdnullerror;
	md_error_t	*ep	= &status;
	int		rc	= 0;
	mdname_t	*mdnms[2];
	int		c, i;
	int		error;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	int		origargc = argc;
	char		**origargv = argv;
	char		*miscname;

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
	while ((c = getopt(argc, argv, "fns:xh?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			break;

		case 'x':
			++xflag;
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

	if (argc != 2) {
		usage(sp, 1);
	}

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
		int	result;
		int	i;
		int	newargc;
		char	**newargv;

		/*
		 * For MN sets we start a dryrun version of this command
		 * before sending out the real version.
		 * Thus we need a new array for the arguments as the first
		 * one will be -n to indicate the dryrun
		 */
		newargv = calloc(origargc+1, sizeof (char *));
		newargv[0] = "metarename";
		newargv[1] = "-n"; /* always do "-n" first */
		newargc = 2;
		for (i = 1; i < origargc; i++, newargc++)
			newargv[newargc] = origargv[i];

		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_DRYRUN, NO_CONTEXT_STRING, ep);

		/* If we found a problem don't do it for real */
		if (result != 0) {
			md_exit(sp, result);
		}

		/*
		 * Do it for real now. Remove "-n" from the arguments and
		 * MD_DRYRUN from the flags. If this fails, the master must
		 * panic as the mddb may be inconsistent.
		 */
		newargv[1] = ""; /* this was "-n" before */
		result = meta_mn_send_command(sp, newargc, newargv,
		    MD_DISP_STDERR | MD_RETRY_BUSY | MD_PANIC_WHEN_INCONSISTENT,
		    NO_CONTEXT_STRING, ep);
		free(newargv);

		md_exit(sp, result);
	}

	for (i = 0; i < 2; i++) {
		if (!is_metaname(argv[i])) {
			/*
			 * one of the input devices is not a valid
			 * metadevice name
			 */
			usage(sp, 1);
		}
		if (i == 1 && !xflag) {
		    /* rename, create dest metadevice name */
		    if (meta_init_make_device(&sp, argv[i], ep) <= 0) {
			mde_perror(ep, argv[i]);
			md_exit(sp, 1);
		    }
		}

		if ((mdnms[i] = metaname(&sp, argv[i],
		    META_DEVICE, ep)) == NULL) {
			mde_perror(ep, argv[i]);
			md_exit(sp, 1);
		}
	}

	/*
	 * The FORCE option is only valid for a trans metadevice, clear it if
	 * it is not trans
	 */
	if ((miscname = metagetmiscname(mdnms[0], ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (strcmp(miscname, MD_TRANS) != 0) {
		options &= ~MDCMD_FORCE;
	}

	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (xflag) {
		rc = meta_exchange(sp, mdnms[0], mdnms[1], options, ep);
	} else {
		rc = meta_rename(sp, mdnms[0], mdnms[1], options, ep);
	}
out:
	if (rc != 0 || !mdisok(ep)) {
		mde_perror(ep, "");
	}
	md_exit(sp, rc);
	/*NOTREACHED*/
	return (rc);
}
