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
 * patch system files for root on metadevice
 */

#include <meta.h>
#include <stdlib.h>
#include <sdssc.h>

#define	METAROOT_OK 0
#define	METAROOT_ERR -1
#define	METAROOT_NOTFOUND -2

struct def_map {
	char		**dm_fname;	/* Location of file name */
	char		*dm_default;	/* Default name */
};

/*
 * options
 */
static	char	*cname = NULL;	/* take default */
static	char	*sname = NULL;	/* take default */
static	char	*vname = NULL;	/* take default */
static	char	*dbname = NULL;	/* take default bootlist location */
static	int	doit = 1;
static	int	verbose = 0;

/*
 * Map of default system file names to the place where they are stored.
 * This is used if the -R option is specified.  Note that the members of
 * the map point to the cname, sname, vname and dbname global variables
 * above.  These global variables are used in the call to
 * meta_patch_rootdev() in main().
 */
static struct def_map	default_names[] = {
	&cname, META_DBCONF,
	&sname, "/etc/system",
	&vname, "/etc/vfstab",
	&dbname, "/kernel/drv/md.conf"
};

static int validate_stripe_root();

/*
 * print usage message, md_exit
 */
static void
usage(
	mdsetname_t	*sp,
	int		eval
)
{
	(void) fprintf(stderr, gettext("\
usage:\t%s [-n] [-k system-name] [-m md.conf-name] [-v vfstab-name] \\\n\
\t\t[-c mddb.cf-name] device\n\
\t%s [-n] [-R root-path] device\n"),
	    myname, myname);
	md_exit(sp, eval);
}

static void
free_mem()
{
	int			i;
	struct def_map		*map;

	for (i = 0, map = default_names;
		i < sizeof (default_names) / sizeof (struct def_map);
		i++, map++) {
		if (*map->dm_fname != NULL) {
			free((void *) *map->dm_fname);
			*map->dm_fname = NULL;
		}
	}
}

/*
 * Check if mirror, mirnp, is a valid root filesystem, ie all
 * submirrors must be single disk stripe, and that the slice, slicenp,
 * if not NULL, is a component of one of the submirrors.
 * The arg metaroot is TRUE if mirnp is the current root filesystem.
 * Returns:
 * METAROOT_OK		if mirror is valid and slicenp is a component
 * METAROOT_NOTFOUND	if mirror valid but slicenp not a component
 * METAROOT_ERR		if mirror not a valid root
 */
static int
validate_mirror_root(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdname_t	*slicenp,
	int		metaroot,
	md_error_t	*ep
)
{
	int 		smi;
	md_mirror_t	*mirrorp;
	char		*miscname;
	int		found = 0;
	int		rval;
	int		err = 0;

	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL) {
		mde_perror(ep, "");
		return (METAROOT_ERR);
	}

	for (smi = 0; (smi < NMIRROR); ++smi) {
		/* Check all submirrors */
		md_submirror_t  *mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep = mdsp->submirnamep;

		/* skip unused submirrors */
		if (submirnamep == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}
		if ((miscname = metagetmiscname(submirnamep, ep)) == NULL) {
			return (mdmderror(ep, MDE_UNKNOWN_TYPE,
					meta_getminor(submirnamep->dev),
					submirnamep->cname));
		}
		if (strcmp(miscname, MD_STRIPE) != 0) {
			md_eprintf(gettext("Submirror is not a stripe\n"));
			return (METAROOT_ERR);
		}
		rval = validate_stripe_root(sp, submirnamep, slicenp,
		    metaroot, ep);
		switch (rval) {
		case METAROOT_OK:
			found = 1;
			break;
		case METAROOT_ERR:
			err++;
			break;
		case METAROOT_NOTFOUND:
		default:
			break;
		}
	}
	if (err > 0)
		return (METAROOT_ERR);
	if (!found)
		return (METAROOT_NOTFOUND);
	return (METAROOT_OK);
}

/*
 * Check if stripe, strnp, is a valid root filesystem, ie must
 * be single disk stripe, and the the slice, slicenp, if not NULL, must
 * be a component of this stripe.
 * The arg metaroot is TRUE if strnp is the current root filesystem.
 * Returns:
 * METAROOT_OK		if stripe is valid and slicenp is a component
 * METAROOT_NOTFOUND	if stripe valid but slicenp not a component
 * METAROOT_ERR		if stripe not a valid root
 */
static int
validate_stripe_root(
	mdsetname_t	*sp,
	mdname_t	*strnp,
	mdname_t	*slicenp,
	int		metaroot,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	md_row_t	*rp;
	md_comp_t	*cp;

	if ((stripep = meta_get_stripe(sp, strnp, ep)) == NULL) {
		mde_perror(ep, "");
		return (METAROOT_ERR);
	}
	if (stripep->rows.rows_len != 1) {
		md_eprintf(gettext(
		    "Concat %s has more than 1 slice\n"), strnp->cname);
		return (METAROOT_ERR);
	}
	rp = &stripep->rows.rows_val[0];

	if (rp->comps.comps_len != 1) {
		md_eprintf(gettext(
		    "Stripe %s has more than 1 slice\n"), strnp->cname);
		return (METAROOT_ERR);
	}
	cp = &rp->comps.comps_val[0];
	if (!metaismeta(cp->compnamep)) {
		if (slicenp == NULL)
			return (METAROOT_OK);
		if (strcmp(slicenp->cname, cp->compnamep->cname) == 0)
			return (METAROOT_OK);
		if (!metaroot) {
			md_eprintf(gettext(
			    "Root %s is not a component of metadevice %s\n"),
			    slicenp->cname, strnp->cname);
		}
		return (METAROOT_NOTFOUND);
	}
	md_eprintf(gettext(
	    "Component %s is not a stripe\n"), cp->compnamep->cname);
	return (METAROOT_ERR);
}

/*
 * Check if the device devnp is valid. It must be a component of the
 * metadevice that contains the root filesystem
 */

static int
validate_root_device(
	mdsetname_t	*sp,
	mdname_t	*devnp,
	md_error_t	*ep
)
{
	mdname_t	*rootnp;
	char		*curroot;
	char		*miscname;
	int		rval;

	if ((curroot = meta_get_current_root(ep)) == NULL) {
		mde_perror(ep, "");
		return (METAROOT_ERR);
	}
	if ((rootnp = metaname(&sp, curroot, UNKNOWN, ep)) == NULL) {
		mde_perror(ep, "");
		return (METAROOT_ERR);
	}

	if (metaismeta(rootnp)) {
		/* get type */
		if ((miscname = metagetmiscname(rootnp, ep)) == NULL) {
			mde_perror(ep, "");
			return (METAROOT_ERR);
		}
		if (strcmp(miscname, MD_MIRROR) == 0) {
			if ((rval = validate_mirror_root(sp, rootnp,
			    devnp, 1, ep)) == METAROOT_OK)
				return (METAROOT_OK);
			if (rval == METAROOT_NOTFOUND) {
				md_eprintf(gettext(
				    "Slice %s is not a component of root %s\n"),
				    devnp->cname, rootnp->cname);
			}
			return (METAROOT_ERR);
		} else if (strcmp(miscname, MD_STRIPE) == 0) {
			if ((rval = validate_stripe_root(sp, rootnp,
			    devnp, 1, ep)) == METAROOT_OK)
				return (METAROOT_OK);
			if (rval == METAROOT_NOTFOUND) {
				md_eprintf(gettext(
				    "Slice %s is not a component of root %s\n"),
				    devnp->cname, rootnp->cname);
			}
			return (METAROOT_ERR);
		} else {
			md_eprintf(gettext(
			    "Root metadevice, %s, is not a Slice or Mirror\n"),
			    rootnp->cname);
			return (METAROOT_ERR);
		}
	} else {
		md_eprintf(gettext(
		    "Current Root %s is not a metadevice\n"), rootnp->cname);
		return (METAROOT_ERR);
	}
}

/*
 * What we're going to do:
 *
 * 1) Check if the device is a metadevice or not.
 *
 * 2) If a metadevice, and it is valid, ie a stripe or a mirror containing
 *    a single slice, add "forceload:{drv,misc}/<modname>" of
 *    underlying drivers for the meta-root and the metadevice
 *    database to system. Otherwise, remove forceloads from system if the
 *    slice is a component of the current root metadevice.
 *
 * 3) Add "rootdev:/devices/..." to system.
 *
 * 4) Replace / mount in vfstab.
 *
 * 5) Repatch database locations, just to be safe.
 */
int
main(
	int		argc,
	char		*argv[]
)
{
	int		i;
	mdsetname_t	*sp = NULL;
	mdname_t	*rootnp;
	int		c;
	int		ckmv_flag = 0;	/* non-zero if -c, -k, -m or -v */
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	char		*miscname;
	char		*curroot;
	mdname_t	*currootnp;
	mdname_t	*currootdevnp;
	char		*root_path = NULL;
	struct def_map	*map;
	size_t		root_path_size;
	size_t		path_buf_size;
	int		error;

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

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0 ||
			meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse options */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "hnk:m:v:c:R:?")) != -1) {
		switch (c) {
		case 'h':
			usage(sp, 0);
			break;
		case 'm':
			dbname = optarg;
			ckmv_flag = 1;
			break;
		case 'n':
			doit = 0;
			verbose = 1;
			break;
		case 'k':
			sname = optarg;
			ckmv_flag = 1;
			break;
		case 'v':
			vname = optarg;
			ckmv_flag = 1;
			break;
		case 'c':
			cname = optarg;
			ckmv_flag = 1;
			break;
		case 'R':
			root_path = optarg;
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
	if (argc != 1)
		usage(sp, 1);

	/* Can't use -R with any of -c, -k, -m or -v */
	if ((ckmv_flag != 0) && (root_path != NULL)) {
		md_eprintf(
			gettext("-R invalid with any of -c, -k, -m or -v\n"));
		usage(sp, 1);
	}

	/* get device name */
	if ((rootnp = metaname(&sp, argv[0], UNKNOWN, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	if ((curroot = meta_get_current_root(ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	/*
	 * Get device name of current root metadevice.  If root is net
	 * mounted as happens if this command is part of the install
	 * process, currootnp will be set to NULL.
	 */
	currootnp = metaname(&sp, curroot, UNKNOWN, ep);
	/*
	 * If the argument is the name of the current root filesystem, then
	 * the command is allowed, otherwise check that the argument is
	 * valid.
	 */
	if ((currootnp == NULL) ||
		(strcmp(currootnp->cname, rootnp->cname) != 0)) {
		if (metaismeta(rootnp)) {
			/*
			 * Validate that the metadevice is based on a
			 * single slice. If none of the -k, -m, -v, -c or
			 * -R options are specified, then the default
			 * system files are being modified and hence the
			 * current root slice must be a component of the
			 * metadevice. If any of the previously mentioned
			 * options are used don't check that the current
			 * root is a component.
			 */
			if ((ckmv_flag == 0) && (root_path == NULL)) {
				/* Get device name of current root slice */
				if ((currootdevnp =
				    meta_get_current_root_dev(sp, ep))
				    == NULL) {
					mde_perror(ep, "");
					md_exit(sp, 1);
				}
			} else currootdevnp = NULL;

			if ((miscname = metagetmiscname(rootnp, ep)) == NULL) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			}
			/* Check that metadevice is a mirror or a stripe */
			if (strcmp(miscname, MD_MIRROR) == 0) {
				if (validate_mirror_root(sp, rootnp,
				    currootdevnp, 0, ep) != METAROOT_OK) {
					md_exit(sp, 1);
				}
			} else if (strcmp(miscname, MD_STRIPE) == 0) {
				if (validate_stripe_root(sp, rootnp,
				    currootdevnp, 0, ep) != METAROOT_OK) {
					md_exit(sp, 1);
				}
			} else {
				md_eprintf(gettext(
				    "%s is not a mirror or stripe\n"),
				    rootnp->cname);
				md_exit(sp, 1);
			}
		} else {
			/*
			 * Check that the root device is a component of the
			 * current root filesystem only if the default system
			 * files are being modified
			 */
			if ((ckmv_flag == 0) && (root_path == NULL)) {
				if (validate_root_device(sp, rootnp, ep) != 0) {
					md_exit(sp, 1);
				}
			}
		}
	}

	if (meta_lock(sp, TRUE, ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/*
	 * If -R is specified, use the default system file names relative
	 * to the new root location.
	 */
	if (root_path != NULL) {
		root_path_size = strlen(root_path);
		for (i = 0, map = default_names;
			i < sizeof (default_names) / sizeof (struct def_map);
			i++, map++) {
			/* Add 1 for null terminator */
			path_buf_size = root_path_size +
				strlen(map->dm_default) + 1;
			*map->dm_fname = malloc(path_buf_size);
			if (*map->dm_fname == NULL) {
				md_eprintf(gettext("Cannot allocate memory \
for system file path relocation\n"));
				md_exit(sp, 1);
			}
			(void) snprintf(*map->dm_fname, path_buf_size,
					"%s%s", root_path, map->dm_default);
		}
	}

	/* patch system and vfstab for root and mddb locations */
	if (meta_patch_rootdev(rootnp, sname, vname, cname, dbname, doit,
	    verbose, ep) != 0) {
		if (root_path != NULL) {
			free_mem();
		}
		mde_perror(ep, "");
		md_exit(sp, 1);
	}
	if (root_path != NULL) {
		free_mem();
	}

	/* return success */
	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
