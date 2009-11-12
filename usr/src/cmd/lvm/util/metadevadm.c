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

#include	<stdio.h>
#include	<stdarg.h>
#include	<ctype.h>
#include	<sys/fcntl.h>
#include	<sys/types.h>
#include	<devid.h>
#include	<ftw.h>
#include	<string.h>
#include	<mdiox.h>
#include	<sys/lvm/mdio.h>
#include 	<meta.h>
#include 	<syslog.h>
#include	<sdssc.h>

/*
 * print usage message
 */
static void
usage(char *myname)
{
	(void) fprintf(stderr, gettext(
	    "usage:  %s -h\n"
	    "	%s [-s setname] -r [-lnv]\n"
	    "	%s [-s setname] -u cxtxdx [-lnv]\n"),
	    myname, myname, myname);
}

int
main(int argc, char **argv)
{
	char		c;
	char		*sname = MD_LOCAL_NAME;
	mddevopts_t	options = 0;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	mdsetname_t	*sp = NULL;
	mdsetname_t	*local_sp = NULL;
	char		*argname;
	int		todo = 0;
	int		ret = 0;
	int		md_upgd_stat = 0;
	int		error;
	md_set_desc	*sd;

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

	if ((sdssc_bind_library() == SDSSC_OKAY) &&
	    (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
	    &error) == SDSSC_PROXY_DONE))
		exit(error);

	openlog("metadevadm", LOG_ODELAY, LOG_USER);

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0 ||
	    meta_check_root(ep) != 0) {
		closelog();
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse args */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "vlhnrs:u:")) != -1) {
		switch (c) {
		case 'v':
			options |= DEV_VERBOSE;
			break;
		case 'n':
			options |= DEV_NOACTION;
			break;
		case 'r':
			options |= DEV_RELOAD;
			todo = 1;
			break;
		case 's':
			sname = optarg;
			break;
		case 'u':
			todo = 1;
			options |= DEV_UPDATE;
			argname = optarg;
			if (argname == NULL) {
				usage("metadevadm");
				closelog();
				md_exit(sp, 0);
			}
			break;
		case 'l':
			options |= DEV_LOG;
			break;
		case 'h':
		default:
			usage("metadevadm");
			closelog();
			md_exit(sp, 0);
		}
	}

	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		closelog();
		md_exit(sp, 1);
	}

	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			mde_perror(ep, "");
			closelog();
			md_exit(sp, 1);
		}
		if (MD_MNSET_DESC(sd)) {
			(void) printf("%s\n", gettext("metadevadm cannot be "
			    "run on multi-owner disksets\n"));
			closelog();
			md_exit(sp, 0);
		}
	}

	if ((options & DEV_VERBOSE) && (todo != 1)) {
		usage("metadevadm");
		closelog();
		md_exit(sp, 0);
	}

	if ((options & DEV_NOACTION) && (todo != 1)) {
		usage("metadevadm");
		closelog();
		md_exit(sp, 0);
	}

	if (todo == 0) {
		usage("metadevadm");
		closelog();
		md_exit(sp, 0);
	}

	if ((local_sp = metasetname(MD_LOCAL_NAME, ep)) == NULL) {
		mde_perror(ep, "");
		closelog();
		md_exit(local_sp, 1);
	}

	/* lock the local set */
	if (meta_lock(local_sp, TRUE, ep) != 0) {
		mde_perror(ep, "");
		closelog();
		md_exit(local_sp, 1);
	}

	/* grab set lock */
	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		closelog();
		md_exit(local_sp, 1);
	}

	/* check for ownership */
	if (meta_check_ownership(sp, ep) != 0) {
		/*
		 * If the set is not owned by this node then only update the
		 * local set's replica.
		 */
		options |= DEV_LOCAL_SET;
	}

	/*
	 * check for upgrade. If upgrade in progress then just exit.
	 */
	if (metaioctl(MD_UPGRADE_STAT, &md_upgd_stat, ep, NULL) != 0) {
			mde_perror(ep, "");
			closelog();
			(void) meta_unlock(sp, ep);
			md_exit(local_sp, 1);
	}
	if (md_upgd_stat == 0) {
		ret = meta_fixdevid(sp, options, argname, ep);
		if (ret == METADEVADM_ERR) {
			/*
			 * If the call failed, for a DEV_RELOAD still need to
			 * update the .conf file to provide the latest devid
			 * information so exit later.
			 */
			if (options & DEV_UPDATE) {
				closelog();
				(void) meta_unlock(sp, ep);
				md_exit(local_sp, 1);
			}
		}
	}

	/*
	 * Sync replica list in kernel to replica list in conf files.
	 * This will update driver name and minor number in conf file
	 * if reload was run.  Will update device id in conf file if
	 * update was run.
	 */
	meta_sync_db_locations(sp, ep);
	closelog();
	(void) meta_unlock(sp, ep);
	md_exit(local_sp, ret);
	return (0);
}
