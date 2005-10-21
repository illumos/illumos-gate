/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility to import SVM disksets into an active SVM configuration.
 */

#include <assert.h>
#include <strings.h>
#include <string.h>
#include <meta.h>
#include <sys/utsname.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_names.h>
#include <sdssc.h>

static md_im_drive_info_t	*overlap_disks = NULL;

static void
usage(mdsetname_t *sp, char *string)
{
	if ((string != NULL) && (*string != '\0'))
		md_eprintf("%s\n", string);

	(void) fprintf(stderr,
	    "%s:\t%s -s setname [-n] [-f] [-v] [%s...]\n",
	    gettext("usage"), myname, gettext("disk"));
	(void) fprintf(stderr, "        %s -r [%s...]\n",
	    myname, gettext("disk"));
	(void) fprintf(stderr, "        %s -?\n", myname);
	(void) fprintf(stderr, "        %s -V\n", myname);

	md_exit(sp, (string == NULL) ? 0 : 1);
}

static void
print_version(mdsetname_t *sp)
{
	struct utsname curname;

	if (uname(&curname) == -1) {
		md_eprintf("%s\n", strerror(errno));
		md_exit(sp, 1);
	}

	(void) fprintf(stderr, "%s %s\n", myname, curname.version);

	md_exit(sp, 0);
}

/*
 * Returns 0 if there is no overlap, 1 otherwise
 */
static int
set_disk_overlap(md_im_set_desc_t *misp)
{

	md_im_set_desc_t *next, *isp = misp;
	md_im_drive_info_t *set_dr, *next_set_dr, **chain;
	int	is_overlap = 0;

	for (; isp != NULL; isp = isp->mis_next) {
	    for (next = isp->mis_next; next != NULL; next = next->mis_next) {

		for (set_dr = isp->mis_drives; set_dr != NULL;
			set_dr = set_dr->mid_next) {

			for (next_set_dr = next->mis_drives;
			    next_set_dr != NULL;
			    next_set_dr = next_set_dr->mid_next) {
			    if (strcmp(set_dr->mid_dnp->cname,
				next_set_dr->mid_dnp->cname) == 0) {
				/*
				 * Chain it, skip if already there
				 */
				if (overlap_disks == NULL) {
					set_dr->overlap = NULL;
					overlap_disks = set_dr;
				} else {
				    for (chain = &overlap_disks;
					*chain != NULL;
					chain = &(*chain)->overlap) {
					if (strcmp(set_dr->mid_dnp->cname,
					    (*chain)->mid_dnp->cname)
					    == 0)
						break;
				    }

				    if (*chain == NULL) {
					*chain = set_dr;
					set_dr->overlap = NULL;
				    }
				}
				if (!is_overlap)
					is_overlap = 1;
			    }
			}
		}
	    }
	}

	return (is_overlap);
}

static void
report_overlap_recommendation()
{
	mddb_mb_t		*mbp;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	md_im_drive_info_t	*d;

	(void) fprintf(stdout, "%s\n", gettext("Warning:  The following disks "
	    "have been detected in more than one set.\n"
	    "Import recommendation based upon set creation time.\n"
	    "Proceed with the import with caution."));

	/*
	 * Look at all overlapping disks. Determine which slice
	 * would have a replica on it. i.e. either slice 7 or 6.
	 * Then read the master block. If the disk doesn't have a
	 * metadb on it, the master block is a dummy master block.
	 * Both dummy or normal master block contain the timestamp
	 * which is what we are after. Use this timestamp to issue
	 * the appropriate recommendation.
	 */
	mbp = Malloc(DEV_BSIZE);
	for (d = overlap_disks; d != NULL; d = d->overlap) {
		mdname_t	*rsp;
		uint_t		sliceno;
		int		fd = -1;

		if (meta_replicaslice(d->mid_dnp, &sliceno, ep) != 0)
			continue;

		if (d->mid_dnp->vtoc.parts[sliceno].size == 0)
			continue;

		if ((rsp = metaslicename(d->mid_dnp, sliceno, ep)) == NULL)
			continue;
		if ((fd = open(rsp->rname, O_RDONLY| O_NDELAY)) < 0)
			continue;
		if (read_master_block(ep, fd, mbp, DEV_BSIZE) <= 0) {
			(void) close(fd);
			mdclrerror(ep);
			continue;
		}
		(void) close(fd);
		fprintf(stdout, "  %s ", d->mid_dnp->cname);
		    (void) fprintf(stdout, "%s: %s\n",
		    gettext(" - recommend importing with set "
		    "created at "), meta_print_time((md_timeval32_t *)
		    (&(mbp->mb_setcreatetime))));
	}
	Free(mbp);
}


int
main(int argc, char *argv[])
{
	char			c;
	md_error_t		status = mdnullerror;
	md_error_t		*ep = &status;
	mdsetname_t		*sp = NULL;
	char			*setname_new = NULL;
	int			report_only = 0;
	int			version = 0;
	bool_t			dry_run = 0;
	md_im_names_t		cnames = { 0, NULL };
	int			err_on_prune = 0;
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	*dp;
	mddrivenamelist_t	*skiph = NULL;
	mddrivenamelist_t	**skipt = &skiph;
	int			rscount = 0;
	int			hasreplica;
	md_im_set_desc_t	*misp = NULL;
	md_im_set_desc_t	**mispp = &misp;
	mhd_mhiargs_t		mhiargs = defmhiargs;
	int			have_multiple_sets = 0;
	int			force = 0;
	int			overlap = 0;
	int			partial = 0;
	uint_t			imp_flags = 0;
	int			set_count = 0;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to output.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Check to see if the libsds_sc.so is bound on the
	 * current system. If it is, it means the system is
	 * part of a cluster.
	 *
	 * The import operation is currently not supported
	 * in a SunCluster environment.
	 */
	if (sdssc_bind_library() != SDSSC_NOT_BOUND) {
		printf(gettext(
		    "%s: Import operation not supported under SunCluster\n"),
		    argv[0]);
		exit(0);
	}

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	optind = 1;
	opterr = 1;

	while ((c = getopt(argc, argv, "frns:vV?")) != -1) {
		switch (c) {

		case 'f':
			force = 1;
			break;

		case 'n':
			dry_run = 1;
			break;

		case 'r':
			report_only = 1;
			imp_flags |= META_IMP_REPORT;
			break;

		case 's':
			setname_new = optarg;
			break;

		case 'v':
			imp_flags |= META_IMP_VERBOSE;
			break;

		case 'V':
			version = 1;
			break;

		case '?':
		default:
			usage(sp, NULL);
			break;
		}
	}

	if (version == 1)
		print_version(sp);

	/* Detect conflicting options */
	if ((dry_run != 0) && (report_only != 0))
		usage(sp, gettext("The -n and -r options conflict."));

	if ((report_only != 0) && (setname_new != NULL))
		usage(sp, gettext("The -r and -s options conflict."));

	if ((report_only == 0) && (setname_new == NULL))
		usage(sp, gettext("You must specify either -r or -s."));

	/* Don't do any real work if we don't have root privilege */
	if (meta_check_root(ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_setup_db_locations(ep) != 0) {
		mde_perror(ep, "");
		if (mdismddberror(ep, MDE_DB_STALE))
			md_exit(sp, 66);
		if (! mdiserror(ep, MDE_MDDB_CKSUM))
			md_exit(sp, 1);
	}

	/*
	 * Read remaining arguments into drive name list, otherwise
	 * call routine to list all drives in system.
	 */
	if (argc > optind) {
		int i;

		/* For user specified disks, they MUST not be in use */
		err_on_prune = 1;

		/* All remaining args should be disks */
		cnames.min_count = argc - optind;
		cnames.min_names = Malloc(cnames.min_count * sizeof (char *));

		for (i = 0; i < cnames.min_count; i++, optind++) {
			mddrivename_t *dnp;
			dnp = metadrivename(&sp, argv[optind], ep);
			if (dnp == NULL) {
				mde_perror(ep, "");
				md_exit(sp, 1);
			} else {
				cnames.min_names[i] = dnp->rname;
			}
		}
	} else {
		if (meta_list_disks(ep, &cnames) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
	}

	/*
	 * If the user specified disks on the command line, min_count will be
	 * greater than zero.  If they didn't, it should be safe to assume that
	 * the system in question has at least one drive detected by the
	 * snapshot code, or we would have barfed earlier initializing the
	 * metadb.
	 */
	assert(cnames.min_count > 0);

	/*
	 * Prune the list:
	 * - get rid of drives in current svm configuration
	 * - get rid of mounted drives
	 * - get rid of swap drives
	 * - get rid of drives in other sets
	 *
	 * If drives were specified on the command line, it should be
	 * an error to find in-use disks in the list.  (err_on_prune)
	 *
	 * On return from meta_prune_cnames call, dnlp
	 * will have candidate for replica scan.
	 */
	dnlp = meta_prune_cnames(ep, &cnames, err_on_prune);

	/*
	 * Doctor the drive string in the error structure to list all of the
	 * unused disks, rather than just one.  The output will be done in the
	 * following !mdisok() block.
	 */
	if (mdisdserror(ep, MDE_DS_DRIVEINUSE)) {
		md_ds_error_t		*ip =
		    &ep->info.md_error_info_t_u.ds_error;
		char			*dlist;
		int			sizecnt = 0;

		sizecnt += strlen(ip->drive);
		for (dp = dnlp->next; dp != NULL; dp = dp->next) {
			sizecnt += 2; /* for the ", " */
			sizecnt += strlen(dp->drivenamep->cname);
		}

		dlist = Malloc(sizecnt);

		strlcpy(dlist, ip->drive, sizecnt);
		Free(ip->drive);

		dlist += strlen(ip->drive);
		for (dp = dnlp->next; dp != NULL; dp = dp->next) {
			strlcat(dlist, ", ", sizecnt);
			strlcat(dlist, dp->drivenamep->cname, sizecnt);
		}

		ip->drive = Strdup(dlist);
	}

	/* Don't continue if we're already hosed */
	if (!mdisok(ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* ...or if there's nothing to scan */
	if (dnlp == NULL) {
		md_eprintf("%s\n", gettext("no unused disks detected"));
		md_exit(sp, 0);
	}

	/* Scan qualified disks */
	for (dp = dnlp; dp != NULL; dp = dp->next) {
		mddrivenamelist_t *slp;

		/* is the current drive on the skip list? */
		for (slp = skiph; slp != NULL; slp = slp->next) {
		    if (dp->drivenamep == slp->drivenamep)
			    goto skipdisk;
		}

		/*
		 * In addition to updating the misp list, either verbose or
		 * standard output will be generated.
		 *
		 */
		hasreplica = meta_get_and_report_set_info(dp, mispp, 0,
		    imp_flags, &set_count, ep);

		/*
		 * If current disk is part of a partial diskset,
		 * meta_get_set_info returns an ENOTSUP for this disk.
		 * Import of partial disksets isn't supported yet,
		 * so do NOT put this disk onto any list being set up
		 * by metaimport. The partial diskset error message will
		 * only be printed once when the first partial diskset is
		 * detected. If the user is actually trying to import the
		 * partial diskset, print the error and exit; otherwise,
		 * print the error and continue.
		 */
		if (hasreplica == ENOTSUP) {
			if (report_only) {
			    if (!partial) {
				mde_perror(ep, "");
				partial = 1;
			    }
			    mdclrerror(ep);
			    goto skipdisk;
			} else {
			    mde_perror(ep, "");
			    md_exit(sp, 1);
			}
		}

		if (hasreplica < 0) {
			mde_perror(ep, "");
			mdclrerror(ep);
		} else {
			md_im_set_desc_t	*p;
			md_im_drive_info_t	*d;

			rscount += hasreplica;

			/* Eliminate duplicate reporting */
			if (hasreplica > 0) {
				md_timeval32_t	firstdisktime;

				/*
				 * Go to the tail for the current set
				 */
				for (p = misp; p->mis_next != NULL;
				    p = p->mis_next);
				firstdisktime =
				    p->mis_drives->mid_setcreatetimestamp;
				for (d = p->mis_drives;
				    d != NULL;
				    d = d->mid_next) {
					/*
					 * if the mb_setcreatetime for a disk
					 * is not the same as the first disk
					 * in the set, don't put it on the
					 * skip list. This disk probably
					 * doesn't really belong in this set
					 * and we'll want to look at it again
					 * to figure out where it does belong.
					 */
					if ((d->mid_setcreatetimestamp.tv_sec !=
					    firstdisktime.tv_sec) ||
					    (d->mid_setcreatetimestamp.tv_usec
					    != firstdisktime.tv_usec))
						continue;
					skipt =
					    meta_drivenamelist_append_wrapper(
						skipt, d->mid_dnp);
				}
			}
		}

skipdisk:
		;
	}

	/*
	 * Now have entire list of disks associated with diskset including
	 * disks listed in mddb locator blocks and namespace. Before importing
	 * diskset need to recheck that none of these disks is already in use.
	 * If a disk is found that is already in use, print error and exit.
	 */
	if (!report_only) {
		md_im_set_desc_t	*p;
		md_im_drive_info_t	*d;
		mddrivename_t		*dnp;

		for (p = misp; p != NULL; p = p->mis_next) {
			for (d = p->mis_drives; d != NULL; d = d->mid_next) {
				dnp = d->mid_dnp;
				if (meta_imp_drvused(sp, dnp, ep)) {
					(void) mddserror(ep,
						MDE_DS_DRIVEINUSE, 0, NULL,
						dnp->cname, NULL);
					mde_perror(ep, "");
					md_exit(sp, 0);
				}
			}
		}
	}

	/*
	 * If there are no unconfigured sets, then our work here is done.
	 * Hopefully this is friendlier than just not printing anything at all.
	 */
	if (rscount == 0) {
		/*
		 * If we've found partial disksets but no complete disksets,
		 * we don't want this to print.
		 */
		if (!partial) {
			md_eprintf("%s\n", gettext("no unconfigured sets "
			    "detected"));
		}
		md_exit(sp, 0);
	}

	/*
	 * We'll need this info for both the report content and the import
	 * decision.  By the time we're here, misp should NOT be NULL (or we
	 * would have exited in the rscount == 0 test above).
	 */
	assert(misp != NULL);
	if (misp->mis_next != NULL) {
		have_multiple_sets = 1;
	}
	/*
	 * Generate the appropriate (verbose or not) report for all sets
	 * detected.  If we're planning on importing later, only include the
	 * "suggested import" command if multiple sets were detected.  (That
	 * way, when we error out later, we have still provided useful
	 * information.)
	 */

	/*
	 * Now we should have all the unconfigured sets detected
	 * check for the overlapping
	 */
	if (have_multiple_sets) {
		/* Printing out how many candidate disksets we found. */
		if (imp_flags & META_IMP_REPORT) {
			(void) printf("%s: %i\n\n",
			    gettext("Number of disksets eligible for import"),
			    set_count);
		}

		overlap = set_disk_overlap(misp);
		if (overlap) {
			report_overlap_recommendation();
		}

		if (!report_only) {
			md_eprintf("%s\n\n", gettext("multiple unconfigured "
			    "sets detected.\nRerun the command with the "
			    "suggested options for the desired set."));
		}
	}


	/*
	 * If it's a report-only request, we're done.  If it's an import
	 * request, make sure that we only have one entry in the set list.
	 */

	if (report_only) {
		md_exit(sp, 0);
	} else if (have_multiple_sets) {
		md_exit(sp, 1);
	}

	if (setname_new == NULL) {
		usage(sp, gettext("You must specify a new set name."));
	}

	(void) meta_imp_set(misp, setname_new, force, dry_run, ep);

	if (dry_run) {
		md_exit(sp, 0);
	}

	if (!mdisok(ep)) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if ((sp = metasetname(setname_new, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (meta_lock_nowait(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 10);	/* special errcode */
	}

	if (meta_set_take(sp, &mhiargs, 0, 0, &status)) {
		mde_perror(&status, "");
		md_exit(sp, 1);
	}

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (0);
}
