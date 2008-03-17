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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sync metadevices
 */

#include <meta.h>

#include <sys/lvm/md_mirror.h>

#include <ctype.h>

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
usage:	%s [-s setname] -r [buffer_size]\n\
	%s [-s setname] [buffer_size] metadevices...\n\
	%s [-s setname] -c metadevices...\n"),
	    myname, myname, myname);
	md_exit(sp, eval);
}

/*
 * crack command line arguments.
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	char		*sname = NULL;
	mdsetname_t	*sp = NULL;
	int		rflag = 0;
	int		pflag = 0;
	daddr_t		size = 0;
	int		c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		rval = 0;
	int		error;
	md_resync_cmd_t	resync_cmd = MD_RESYNC_START;
	bool_t		called_thru_rpc = FALSE;
	char		*cp;
	int		mn_set = FALSE;
	int		cflag = 0;

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
	while ((c = getopt(argc, argv, "phs:rc?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;

		case 's':
			sname = optarg;
			break;

		case 'r':
			++rflag;
			break;

		case 'p':
			++pflag;
			break;

		case 'c':
			++cflag;
			resync_cmd = MD_RESYNC_KILL;
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
	if ((pflag + rflag) > 1) {
		usage(sp, 1);
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	argc -= optind;
	argv += optind;

	if (sname != NULL) {
		if ((sp = metasetname(sname, ep)) == NULL) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/*
	 * look for buffer size. If one is not specified we pass '0' to
	 * the meta_resync_all() call. This uses whatever size has been
	 * configured via md_mirror:md_resync_bufsz
	 * The default value (if not overridden in /etc/system) is
	 * MD_DEF_RESYNC_BUF_SIZE
	 */
	if ((argc > 0) && (isdigit(argv[0][0]))) {
		if ((size = atoi(argv[0])) < 0) {
			md_eprintf(gettext(
			    "illegal buffer size %s\n"),
			    argv[0]);
			md_exit(sp, 1);
		}
		--argc;
		++argv;
	}

	/* sync all devices in set */
	if (rflag) {
		/* get set */
		if (argc != 0)
			usage(sp, 1);
		if ((sp == NULL) &&
		    ((sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) &&
		    (metaget_setdesc(sp, ep) == NULL)) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		assert(sp != NULL);
		/*
		 * For a MN set "metasync -r" can only be called by the
		 * initiator. We must not take the set lock for a MN set as
		 * it will only generate individual metasync commands which
		 * will individually take the lock when executing the
		 * individual metasync commands.
		 * Therefore only take the set lock for non MN sets.
		 */
		if (meta_is_mn_set(sp, ep) == 0) {
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
		}
		/* resync all metadevices in set */
		if (meta_resync_all(sp, size, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		md_exit(sp, 0);
	}

	/* sync specified metadevices */
	if (argc <= 0)
		usage(sp, 1);

	/*
	 * Note that if sp is NULL, meta_is_mn_name() derives sp
	 * from argv[0] which is the metadevice arg
	 */
	if (meta_is_mn_name(&sp, argv[0], ep))
		mn_set = TRUE;

	for (; (argc > 0); --argc, ++argv) {
		mdname_t	*np;
		int		result;

		/* get device */
		if ((np = metaname(&sp, argv[0], META_DEVICE, ep)) == NULL) {
			mde_perror(ep, "");
			rval = -1;
			continue;
		}
		assert(sp != NULL);

		/*
		 * If we are not called through an rpc call and the
		 * set associated with the command is an MN set, send
		 * a setsync message to the master of the set and let it
		 * deal with it.
		 */
		if (!called_thru_rpc && mn_set) {
			if ((result = meta_mn_send_setsync(sp, np, size,
			    ep)) != 0) {
				mde_perror(ep, "Unable to start resync");
				md_exit(sp, result);
			}
			continue;
		}

		/* grab set lock */
		if (meta_lock(sp, TRUE, ep)) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		/* check for ownership */
		if (meta_check_ownership(sp, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);	/* no point in continuing */
		}

		/* resync or regen (raid only) metadevice */
		if (pflag) {
			/* regen */
			if (meta_raid_regen_byname(sp, np, size, ep) != 0) {
				mde_perror(ep, "");
				rval = -1;
				continue;
			}
		} else {
			if (meta_resync_byname(sp, np, size, ep, resync_cmd)
			    != 0) {
				mde_perror(ep, "");
				rval = -1;
				continue;
			}
		}
	}

	/* return success */
	md_exit(sp, rval);
	/*NOTREACHED*/
	return (rval);
}
