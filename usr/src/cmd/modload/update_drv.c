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

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include "addrem.h"
#include "errmsg.h"
#include "plcysubr.h"

/* function prototypes */
static void	usage();
static int	unload_drv(char *, int, int);


/*
 * try to modunload driver.
 * return -1 on failure and 0 on success
 */
static int
unload_drv(char *driver_name, int force_flag, int verbose_flag)
{
	int modid;

	get_modid(driver_name, &modid);
	if (modid != -1) {
		if (modctl(MODUNLOAD, modid) < 0) {
			(void) fprintf(stderr, gettext(ERR_MODUN), driver_name);
			if (force_flag == 0) { /* no force flag */
				if (verbose_flag) {
					(void) fprintf(stderr,
					    gettext(NOUPDATE), driver_name);
				}
				/* clean up and exit. remove lock file */
				err_exit();
			}
			(void) fprintf(stderr, gettext(FORCE_UPDATE),
			    driver_name);

			return (-1);
		}
	}

	return (0);
}


static void
usage()
{
	(void) fprintf(stderr, gettext(UPD_DRV_USAGE));
	exit(1);
}


int
main(int argc, char *argv[])
{
	int	error, opt, major;
	int	cleanup_flag = 0;
	int	update_conf = 1;	/* reload driver.conf by default */
	int	verbose_flag = 0;	/* -v option */
	int	force_flag = 0;		/* -f option */
	int	a_flag = 0;		/* -a option */
	int	d_flag = 0;		/* -d option */
	int	i_flag = 0;		/* -i option */
	int	l_flag = 0;		/* -l option */
	int	m_flag = 0;		/* -m option */
	char	*perms = NULL;
	char	*aliases = NULL;
	char	*basedir = NULL;
	char	*policy = NULL;
	char	*aliases2 = NULL;
	char	*priv = NULL;
	char	*driver_name;
	int	found;
	major_t major_num;
	int	rval;

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*  must be run by root */
	if (getuid() != 0) {
		(void) fprintf(stderr, gettext(ERR_NOT_ROOT));
		exit(1);
	}

	while ((opt = getopt(argc, argv, "m:i:b:p:adlfuvP:")) != EOF) {
		switch (opt) {
		case 'a':
			a_flag++;
			break;
		case 'b':
			update_conf = 0;	/* don't update .conf file */
			basedir = optarg;
			break;
		case 'd':
			d_flag++;
			break;
		case 'f':
			force_flag++;
			break;
		case 'i':
			i_flag++;
			aliases = optarg;
			if (check_space_within_quote(aliases) == ERROR) {
				(void) fprintf(stderr, gettext(ERR_NO_SPACE),
				    aliases);
				exit(1);
			}
			break;
		case 'l':	/* private option */
			l_flag++;
			break;
		case 'm':
			m_flag++;
			perms = optarg;
			break;
		case 'p':
			policy = optarg;
			break;
		case 'v':
			verbose_flag++;
			break;
		case 'P':
			priv = optarg;
			break;
		case '?' :
		default:
			usage();
		}
	}

	/*
	 * check for flags and extra args
	 */
	if ((argv[optind] == NULL) || (optind + 1 != argc)) {
		usage();
	}

	/*
	 * - cannot be adding and removing at the same time
	 * - if -a or -d is specified, it's an error if none of
	 *   -i/-m/-p/-P is specified.
	 */
	if ((a_flag && d_flag) ||
	    ((a_flag || d_flag) &&
	    !m_flag && !i_flag && priv == NULL && policy == NULL)) {
		usage();
	}

	/*
	 * - with -d option or -a option either -i 'identify_name',
	 *	-m 'permission',  -p 'policy' or -P 'priv' should be specified
	 */
	if (m_flag || i_flag || policy != NULL || priv != NULL) {
		if (!(a_flag || d_flag))
			usage();
	}

	driver_name = argv[optind];

	/* set up update_drv filenames */
	if ((build_filenames(basedir)) == ERROR) {
		exit(1);
	}

	/* no lock is needed for listing minor perm entry */
	if (l_flag) {
		list_entry(minor_perm, driver_name, ":");

		return (NOERR);
	}

	/* must be only running version of add_drv/update_drv/rem_drv */
	enter_lock();

	if ((check_perms_aliases(m_flag, i_flag)) == ERROR) {
		err_exit();
	}

	/* update_drv doesn't modify /etc/name_to_major file */
	if ((check_name_to_major(R_OK)) == ERROR)
		err_exit();

	if (priv != NULL && check_priv_entry(priv, a_flag) != 0)
		err_exit();

	if (policy != NULL && (policy = check_plcy_entry(policy, driver_name,
	    d_flag ? B_TRUE : B_FALSE)) == NULL)
		err_exit();

	/*
	 * ADD: -a option
	 * i_flag: update /etc/driver_aliases
	 * m_flag: update /etc/minor_perm
	 * -p: update /etc/security/device_policy
	 * -P: update /etc/security/extra_privs
	 * if force_flag is specified continue w/ the next operation
	 */
	if (a_flag) {
		if (m_flag) {
			/* check if the permissions are valid */
			if ((error = check_perm_opts(perms)) == ERROR) {
				if (force_flag == 0) { /* no force flag */
					exit_unlock();

					return (error);
				}
			}

			/*
			 * update the file, if and only if
			 * we didn't run into error earlier.
			 */
			if ((error != ERROR) &&
			    (error = update_minor_entry(driver_name, perms))) {
				if (force_flag == 0) { /* no force flag */
					exit_unlock();

					return (error);
				}
			}
			cleanup_flag |= CLEAN_NAM_MAJ;

			/*
			 * Notify running system of minor perm change
			 */
			if (basedir == NULL || (strcmp(basedir, "/") == 0)) {
				rval = devfs_add_minor_perm(driver_name,
				    log_minorperm_error);
				if (rval) {
					(void) fprintf(stderr,
					    gettext(ERR_UPDATE_PERM),
					    driver_name);
				}
			}
		}

		if (priv != NULL) {
			(void) append_to_file(driver_name, priv, extra_privs,
			    ',', ":", 0);
			cleanup_flag |= CLEAN_DRV_PRIV;
		}

		if (policy != NULL) {
			if ((error = update_device_policy(device_policy,
			    policy, B_TRUE)) != 0) {
				exit_unlock();
				return (error);
			}
			cleanup_flag |= CLEAN_DEV_POLICY;
		}

		if (i_flag) {
			found = get_major_no(driver_name, name_to_major);
			if (found == ERROR) {
				(void) fprintf(stderr, gettext(ERR_MAX_MAJOR),
				    name_to_major);
				err_exit();
			}

			if (found == UNIQUE) {
				(void) fprintf(stderr,
				    gettext(ERR_NOT_INSTALLED), driver_name);
				err_exit();
			}

			major_num = (major_t)found;

			/*
			 * To ease the nuisance of using update_drv
			 * in packaging scripts, do not require that
			 * existing driver aliases be trimmed from
			 * the command line.  If an invocation asks
			 * to add an alias and it's already there,
			 * drive on.  We implement this by removing
			 * duplicates now and add the remainder.
			 */
			error = trim_duplicate_aliases(driver_name,
			    aliases, &aliases2);
			if (error == ERROR) {
				exit_unlock();
				return (error);
			}

			/*
			 * if the list of aliases to be added is
			 * now empty, we're done.
			 */
			if (aliases2 == NULL)
				goto done;

			/*
			 * unless force_flag is specified check that
			 * path-oriented aliases we are adding exist
			 */
			if ((force_flag == 0) && ((error =
			    aliases_paths_exist(aliases2)) == ERROR)) {
				exit_unlock();
				return (error);
			}

			/* update the file */
			if ((error = update_driver_aliases(driver_name,
			    aliases2)) == ERROR) {
				exit_unlock();
				return (error);
			}

			/* paranoia - if we crash whilst configuring */
			sync();

			/* optionally update the running system - not -b */
			if (update_conf) {
				cleanup_flag |= CLEAN_DRV_ALIAS;
				if (config_driver(driver_name, major_num,
				    aliases2, NULL, cleanup_flag,
				    verbose_flag) == ERROR) {
					err_exit();
				}
			}

		}

done:
		if (update_conf && (i_flag || policy != NULL)) {
			/* load the driver */
			load_driver(driver_name, verbose_flag);
		}

		exit_unlock();

		return (0);
	}


	/*
	 * DELETE: -d option
	 * i_flag: update /etc/driver_aliases
	 * m_flag: update /etc/minor_perm
	 * -p: update /etc/security/device_policy
	 * -P: update /etc/security/extra_privs
	 */
	if (d_flag) {
		int err = NOERR;

		if (m_flag) {
			/*
			 * On a running system, we first need to
			 * remove devfs's idea of the minor perms.
			 * We don't have any ability to do this singly
			 * at this point.
			 */
			if (basedir == NULL || (strcmp(basedir, "/") == 0)) {
				rval = devfs_rm_minor_perm(driver_name,
				    log_minorperm_error);
				if (rval) {
					(void) fprintf(stderr,
					    gettext(ERR_UPDATE_PERM),
					    driver_name);
				}
			}

			if ((error = delete_entry(minor_perm,
			    driver_name, ":", perms)) != NOERR) {
				(void) fprintf(stderr, gettext(ERR_NO_ENTRY),
				    driver_name, minor_perm);
				err = error;
			}
			/*
			 * Notify running system of new minor perm state
			 */
			if (basedir == NULL || (strcmp(basedir, "/") == 0)) {
				rval = devfs_add_minor_perm(driver_name,
				    log_minorperm_error);
				if (rval) {
					(void) fprintf(stderr,
					    gettext(ERR_UPDATE_PERM),
					    driver_name);
				}
			}
		}

		if (i_flag) {
			if ((error = delete_entry(driver_aliases,
			    driver_name, ":", aliases)) != NOERR) {
				(void) fprintf(stderr, gettext(ERR_NO_ENTRY),
				    driver_name, driver_aliases);
				if (err != NOERR)
					err = error;
			}
		}

		if (priv != NULL) {
			if ((error = delete_entry(extra_privs, driver_name, ":",
			    priv)) != NOERR) {
				(void) fprintf(stderr, gettext(ERR_NO_ENTRY),
				    driver_name, extra_privs);
				if (err != NOERR)
					err = error;
			}
		}

		if (policy != NULL) {
			if ((error = delete_plcy_entry(device_policy,
			    policy)) != NOERR) {
				(void) fprintf(stderr, gettext(ERR_NO_ENTRY),
				    driver_name, device_policy);
				if (err != NOERR)
					err = error;
			}
		}

		if (err == NOERR && update_conf) {
			if (i_flag || m_flag) {
				/* try to unload the driver */
				(void) unload_drv(driver_name,
				    force_flag, verbose_flag);
			}
			/* reload the policy */
			if (policy != NULL)
				load_driver(driver_name, verbose_flag);
		}
		exit_unlock();

		return (err);
	}

	/* driver name must exist (for update_conf stuff) */
	major = get_major_no(driver_name, name_to_major);
	if (major == ERROR) {
		err_exit();
	}

	/*
	 * Update driver.conf file:
	 *	First try to unload driver module. If it fails, there may
	 *	be attached devices using the old driver.conf properties,
	 *	so we cannot safely update driver.conf
	 *
	 *	The user may specify -f to force a driver.conf update.
	 *	In this case, we will update driver.conf cache. All attached
	 *	devices still reference old driver.conf properties, including
	 *	driver global properties. Devices attached in the future will
	 *	referent properties in the updated driver.conf file.
	 */
	if (update_conf) {
		(void) unload_drv(driver_name, force_flag, verbose_flag);

		if ((modctl(MODUNLOADDRVCONF, major) != 0) ||
		    (modctl(MODLOADDRVCONF, major) != 0)) {
			(void) fprintf(stderr, gettext(ERR_DRVCONF),
			    driver_name);
			err_exit();
		}

		if (verbose_flag) {
			(void) fprintf(stderr, gettext(DRVCONF_UPDATED),
			    driver_name);
		}
		load_driver(driver_name, verbose_flag);
	}

	exit_unlock();

	return (NOERR);
}
