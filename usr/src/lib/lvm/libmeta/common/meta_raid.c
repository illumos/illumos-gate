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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * RAID operations
 */

#include <stdlib.h>
#include <meta.h>
#include <sys/lvm/md_raid.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_convert.h>
#include <stddef.h>

/*
 * FUNCTION:    meta_get_raid_names()
 * INPUT:       sp      - the set name to get raid from
 *              options - options from the command line
 * OUTPUT:      nlpp    - list of all raid names
 *              ep      - return error pointer
 * RETURNS:     int     - -1 if error, 0 success
 * PURPOSE:     returns a list of all raid in the metadb
 *              for all devices in the specified set
 */
int
meta_get_raid_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	return (meta_get_names(MD_RAID, sp, nlpp, options, ep));
}

/*
 * free raid unit
 */
void
meta_free_raid(
	md_raid_t	*raidp
)
{
	if (raidp->cols.cols_val != NULL) {
		assert(raidp->cols.cols_len > 0);
		Free(raidp->cols.cols_val);
	}
	Free(raidp);
}

/*
 * get raid (common)
 */
md_raid_t *
meta_get_raid_common(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	int			fast,
	md_error_t		*ep
)
{
	mddrivename_t		*dnp = raidnp->drivenamep;
	char			*miscname;
	mr_unit_t		*mr;
	md_raid_t		*raidp;
	uint_t			ncol;
	uint_t			col;
	md_resync_ioctl_t	ri;

	/* must have set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* short circuit */
	if (dnp->unitp != NULL) {
		assert(dnp->unitp->type == MD_METARAID);
		return ((md_raid_t *)dnp->unitp);
	}

	/* get miscname and unit */
	if ((miscname = metagetmiscname(raidnp, ep)) == NULL)
		return (NULL);
	if (strcmp(miscname, MD_RAID) != 0) {
		(void) mdmderror(ep, MDE_NOT_RAID, meta_getminor(raidnp->dev),
		    raidnp->cname);
		return (NULL);
	}
	if ((mr = (mr_unit_t *)meta_get_mdunit(sp, raidnp, ep)) == NULL)
		return (NULL);
	assert(mr->c.un_type == MD_METARAID);

	/* allocate raid */
	raidp = Zalloc(sizeof (*raidp));

	/* allocate columns */
	ncol = mr->un_totalcolumncnt;
	assert(ncol >= MD_RAID_MIN);
	raidp->cols.cols_len = ncol;
	raidp->cols.cols_val = Zalloc(raidp->cols.cols_len *
	    sizeof (*raidp->cols.cols_val));

	/* get common info */
	raidp->common.namep = raidnp;
	raidp->common.type = mr->c.un_type;
	raidp->common.state = mr->c.un_status;
	raidp->common.capabilities = mr->c.un_capabilities;
	raidp->common.parent = mr->c.un_parent;
	raidp->common.size = mr->c.un_total_blocks;
	raidp->common.user_flags = mr->c.un_user_flags;
	raidp->common.revision = mr->c.un_revision;

	/* get options */
	raidp->state = mr->un_state;
	raidp->timestamp = mr->un_timestamp;
	raidp->interlace = mr->un_segsize;
	raidp->orig_ncol = mr->un_origcolumncnt;
	raidp->column_size = mr->un_segsize * mr->un_segsincolumn;
	raidp->pw_count = mr->un_pwcnt;
	assert(raidp->orig_ncol <= ncol);
	if ((mr->un_hsp_id != MD_HSP_NONE) &&
	    ((raidp->hspnamep = metahsphspname(&sp, mr->un_hsp_id,
	    ep)) == NULL)) {
		goto out;
	}

	/* get columns, update unit state */
	for (col = 0; (col < ncol); ++col) {
		mr_column_t	*rcp = &mr->un_column[col];
		md_raidcol_t	*mdrcp = &raidp->cols.cols_val[col];

		/* get column name */
		mdrcp->colnamep = metakeyname(&sp, rcp->un_orig_key, fast, ep);
		if (mdrcp->colnamep == NULL)
			goto out;

		/* override any start_blk */
#ifdef	DEBUG
		if (metagetstart(sp, mdrcp->colnamep, ep) !=
		    MD_DISKADDR_ERROR) {
			assert(mdrcp->colnamep->start_blk <=
			    rcp->un_orig_devstart);
		} else {
			mdclrerror(ep);
		}
#endif	/* DEBUG */
		mdrcp->colnamep->start_blk = rcp->un_orig_devstart;

		/* if hotspared */
		if (HOTSPARED(mr, col)) {
			/* get hotspare name */
			mdrcp->hsnamep = metakeyname(&sp, rcp->un_hs_key,
			    fast, ep);
			if (mdrcp->hsnamep == NULL)
				goto out;

			if (getenv("META_DEBUG_START_BLK") != NULL) {
				if (metagetstart(sp, mdrcp->hsnamep, ep) ==
				    MD_DISKADDR_ERROR)
					mdclrerror(ep);

				if ((mdrcp->hsnamep->start_blk == 0) &&
				    (rcp->un_hs_pwstart != 0))
					md_eprintf(dgettext(TEXT_DOMAIN,
					    "%s: suspected bad start block,"
					    " seems labelled [raid]\n"),
					    mdrcp->hsnamep->cname);

				if ((mdrcp->hsnamep->start_blk > 0) &&
				    (rcp->un_hs_pwstart == 0))
					md_eprintf(dgettext(TEXT_DOMAIN,
					    "%s: suspected bad start block, "
					    " seems unlabelled [raid]\n"),
					    mdrcp->hsnamep->cname);
			}

			/* override any start_blk */
			mdrcp->hsnamep->start_blk = rcp->un_hs_devstart;
		}

		/* get state, flags, and timestamp */
		mdrcp->state = rcp->un_devstate;
		mdrcp->flags = rcp->un_devflags;
		mdrcp->timestamp = rcp->un_devtimestamp;
	}

	/* get resync info */
	(void) memset(&ri, 0, sizeof (ri));
	ri.ri_mnum = meta_getminor(raidnp->dev);
	MD_SETDRIVERNAME(&ri, MD_RAID, sp->setno);
	if (metaioctl(MD_IOCGETSYNC, &ri, &ri.mde, raidnp->cname) != 0) {
		(void) mdstealerror(ep, &ri.mde);
		goto out;
	}
	raidp->resync_flags = ri.ri_flags;
	raidp->percent_dirty = ri.ri_percent_dirty;
	raidp->percent_done = ri.ri_percent_done;

	/* cleanup, return success */
	Free(mr);
	dnp->unitp = (md_common_t *)raidp;
	return (raidp);

	/* cleanup, return error */
out:
	Free(mr);
	meta_free_raid(raidp);
	return (NULL);
}

/*
 * get raid
 */
md_raid_t *
meta_get_raid(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	md_error_t		*ep
)
{
	return (meta_get_raid_common(sp, raidnp, 0, ep));
}

/*
 * check raid for dev
 */
static int
in_raid(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	md_raid_t	*raidp;
	uint_t		col;

	/* should be in the same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* get unit */
	if ((raidp = meta_get_raid(sp, raidnp, ep)) == NULL)
		return (-1);

	/* look in columns */
	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;
		diskaddr_t	col_sblk;
		int		err;

		/* check same drive since metagetstart() can fail */
		if ((err = meta_check_samedrive(np, colnp, ep)) < 0)
			return (-1);
		else if (err == 0)
			continue;

		/* check overlap */
		if ((col_sblk = metagetstart(sp, colnp, ep)) ==
		    MD_DISKADDR_ERROR)
			return (-1);
		if (meta_check_overlap(raidnp->cname, np, slblk, nblks,
		    colnp, col_sblk, -1, ep) != 0) {
			return (-1);
		}
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a raid
 */
int
meta_check_inraid(
	mdsetname_t	*sp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdnamelist_t	*raidnlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each raid */
	if (meta_get_raid_names(sp, &raidnlp, 0, ep) < 0)
		return (-1);
	for (p = raidnlp; (p != NULL); p = p->next) {
		mdname_t	*raidnp = p->namep;

		/* check raid */
		if (in_raid(sp, raidnp, np, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreenamelist(raidnlp);
	return (rval);
}

/*
 * check column
 */
int
meta_check_column(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdchkopts_t	options = (MDCHK_ALLOW_MDDB);

	/* check for soft partitions */
	if (meta_sp_issp(sp, np, ep) != 0) {
		/* make sure we have a disk */
		if (metachkcomp(np, ep) != 0)
			return (-1);
	}

	/* check to ensure that it is not already in use */
	if (meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0) {
		return (-1);
	}

	/* make sure it is in the set */
	if (meta_check_inset(sp, np, ep) != 0)
		return (-1);

	/* make sure its not in a metadevice */
	if (meta_check_inmeta(sp, np, options, 0, -1, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * print raid
 */
static int
raid_print(
	md_raid_t	*raidp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		col;
	int		rval = -1;


	if (options & PRINT_LARGEDEVICES) {
		if ((raidp->common.revision & MD_64BIT_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	if (options & PRINT_FN) {
		if ((raidp->common.revision & MD_FN_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	/* print name and -r */
	if (fprintf(fp, "%s -r", raidp->common.namep->cname) == EOF)
		goto out;

	/*
	 * Print columns. Always print the full path.
	 */
	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*mdrcp = &raidp->cols.cols_val[col];

		if (fprintf(fp, " %s", mdrcp->colnamep->rname) == EOF)
			goto out;
	}

	if (fprintf(fp, " -k") == EOF)
		goto out;

	/* print options */
	if (fprintf(fp, " -i %lldb", raidp->interlace) == EOF)
		goto out;

	if (raidp->pw_count != PWCNT_MIN)
		if (fprintf(fp, " -w %d", raidp->pw_count) == EOF)
			goto out;

	if (raidp->hspnamep != NULL) {
		if (fprintf(fp, " -h %s", raidp->hspnamep->hspname) == EOF)
			goto out;
	}
	if (raidp->orig_ncol != raidp->cols.cols_len) {
		assert(raidp->orig_ncol < raidp->cols.cols_len);
		if (fprintf(fp, " -o %u", raidp->orig_ncol) == EOF)
			goto out;
	}

	/* terminate last line */
	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (rval != 0)
		(void) mdsyserror(ep, errno, fname);
	return (rval);
}

static int
find_resyncing_column(
	md_raid_t *raidp
)
{
	int		col;

	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		if (cp->state & RCS_RESYNC)
			return (col);
	}

	/* No resyncing columns */
	return (-1);
}

/*
 * convert raid state to name
 */
char *
raid_state_to_name(
	md_raid_t	*raidp,
	md_timeval32_t	*tvp,
	uint_t		tstate /* Errored tstate flags */
)
{

	/* grab time */
	if (tvp != NULL)
		*tvp = raidp->timestamp;

	/*
	 * If the device has a transient error state (due to it being DR'ed or
	 * failed) and there has been no I/O to it (the actual device is still
	 * marked as 'Okay') then we cannot know what the state is or what
	 * action to take on it. Therefore report the device as 'Unavailable'.
	 * A subsequent I/O to the device will cause the 'Okay' status to
	 * disappear if the device is actually gone and then we will print out
	 * the appropriate status.  The MD_INACCESSIBLE state is only set
	 * on the raid when we open it or probe it.  One the raid is open
	 * then we will just have regular error status on the device.
	 */
	if (tstate & MD_INACCESSIBLE) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* resyncing */
	if (find_resyncing_column(raidp) >= 0)
		return (dgettext(TEXT_DOMAIN, "Resyncing"));

	/* everything else */
	switch (raidp->state) {
		case RUS_INIT :
			return (dgettext(TEXT_DOMAIN, "Initializing"));
		case RUS_OKAY :
			return (dgettext(TEXT_DOMAIN, "Okay"));
		case RUS_ERRED :
		/*FALLTHROUGH*/
		case RUS_LAST_ERRED :
			return (dgettext(TEXT_DOMAIN, "Needs Maintenance"));
		case RUS_DOI :
			return (dgettext(TEXT_DOMAIN, "Initialization Failed"));
		case RUS_REGEN :
			return (dgettext(TEXT_DOMAIN, "Regen"));
		default :
			return (dgettext(TEXT_DOMAIN, "invalid"));
	} /* switch */
}

static int
find_erred_column(md_raid_t *raidp, rcs_state_t state)
{
	int		col;

	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		if (cp->state & state)
			return (col);
	}

	/* No erred columns */
	return (-1);
}

/*
 * convert raid state to repair action
 */
char *
raid_state_to_action(md_raid_t *raidp)
{
	static char	emsg[1024];
	mdname_t	*raidnp = raidp->common.namep;
	int		err_col;

	/* first check for full init failure */
	if (raidp->state & RUS_DOI) {
		(void) snprintf(emsg, sizeof (emsg),
		    "metaclear -f %s", raidnp->cname);
		return (emsg);
	}

	/* replace errored or init errored raid column */
	if ((err_col = find_erred_column(raidp,
	    (RCS_ERRED | RCS_INIT_ERRED))) >= 0) {
		mdname_t	*colnp;

		/* get column with error */
		assert(err_col < raidp->cols.cols_len);
		colnp = raidp->cols.cols_val[err_col].colnamep;
		(void) snprintf(emsg, sizeof (emsg),
		    "metareplace %s%s %s <%s>",
		    ((raidp->state == RUS_LAST_ERRED) ? "-f " : ""),
		    raidnp->cname, colnp->cname,
		    dgettext(TEXT_DOMAIN, "new device"));
		return (emsg);
	}


	/* replace last errored raid column */
	if ((err_col = find_erred_column(raidp, RCS_LAST_ERRED)) >= 0) {
		mdname_t	*colnp;

		assert(err_col < raidp->cols.cols_len);
		colnp = raidp->cols.cols_val[err_col].colnamep;
		(void) snprintf(emsg, sizeof (emsg),
		    "metareplace %s %s %s <%s>",
		    ((raidp->state == RUS_LAST_ERRED) ? "-f " : ""),
		    raidnp->cname, colnp->cname,
		    dgettext(TEXT_DOMAIN, "new device"));
		return (emsg);
	}

	/* OK */
	return (NULL);
}

/*
 * get printable raid column state
 */
char *
raid_col_state_to_name(
	md_raidcol_t	*colp,
	md_timeval32_t	*tvp,
	uint_t		tstate
)
{
	/* grab time */
	if (tvp != NULL)
		*tvp = colp->timestamp;

	if (tstate != 0) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* everything else */
	switch (colp->state) {
	case RCS_INIT:
		return (dgettext(TEXT_DOMAIN, "Initializing"));

	case RCS_OKAY:
		return (dgettext(TEXT_DOMAIN, "Okay"));

	case RCS_INIT_ERRED:
	/*FALLTHROUGH*/
	case RCS_ERRED:
		return (dgettext(TEXT_DOMAIN, "Maintenance"));

	case RCS_LAST_ERRED:
		return (dgettext(TEXT_DOMAIN, "Last Erred"));

	case RCS_RESYNC:
		return (dgettext(TEXT_DOMAIN, "Resyncing"));

	default:
		return (dgettext(TEXT_DOMAIN, "Unknown"));
	}
}

/*
 * print raid column
 */
static int
display_raid_device_info(
	mdsetname_t	*sp,
	md_raidcol_t	*colp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	int		print_len,
	uint_t		top_tstate, /* Errored tstate flags */
	md_error_t	*ep
)
{
	mdname_t	*namep = ((colp->hsnamep != NULL) ?
	    colp->hsnamep : colp->colnamep);
	char 		*devid = "";
	char		*cname = colp->colnamep->cname;
	diskaddr_t	start_blk;
	int		has_mddb;
	char		*has_mddb_str;
	char		*col_state;
	md_timeval32_t	tv;
	char		*hsname = ((colp->hsnamep != NULL) ?
	    colp->hsnamep->cname : "");
	int		rval = -1;
	mdname_t	*didnp = NULL;
	ddi_devid_t	dtp;
	uint_t		tstate = 0;

	/* get info */
	if ((start_blk = metagetstart(sp, namep, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((has_mddb = metahasmddb(sp, namep, ep)) < 0)
		return (-1);
	if (has_mddb)
		has_mddb_str = dgettext(TEXT_DOMAIN, "Yes");
	else
		has_mddb_str = dgettext(TEXT_DOMAIN, "No");

	if (metaismeta(namep)) {
		if (meta_get_tstate(namep->dev, &tstate, ep) != 0)
			return (-1);
		col_state = raid_col_state_to_name(colp, &tv,
		    tstate & MD_DEV_ERRORED);
	} else {
		/*
		 * if top_tstate is set, that implies that you have
		 * a ctd type device with an unavailable metadevice
		 * on top of it. If so, print a - for it's state
		 */
		if (top_tstate != 0)
			col_state = "-";
		else
			col_state = raid_col_state_to_name(colp, &tv, tstate);
	}

	/* populate the key in the name_p structure */
	if ((didnp = metadevname(&sp, namep->dev, ep)) == NULL)
		return (-1);

	/* determine if devid does NOT exist */
	if (options & PRINT_DEVID) {
		if ((dtp = meta_getdidbykey(sp->setno, getmyside(sp, ep),
		    didnp->key, ep)) == NULL)
			devid = dgettext(TEXT_DOMAIN, "No ");
		else {
			devid = dgettext(TEXT_DOMAIN, "Yes");
			free(dtp);
		}
	}
	/* print column */
	/*
	 * Building a format string on the fly that will
	 * be used in (f)printf. This allows the length
	 * of the ctd to vary from small to large without
	 * looking horrible.
	 */
	if (! (options & PRINT_TIMES)) {
		if (fprintf(fp,
		    "\t%-*.*s %8lld     %5.5s %12.12s %5.5s %s\n",
		    print_len, print_len, cname, start_blk, has_mddb_str,
		    col_state, devid, hsname) == EOF) {
			goto out;
		}
	} else {
		char	*timep = meta_print_time(&tv);

		if (fprintf(fp,
		    "\t%-*s %5lld %-5s %-11s %-5s %-9s %s\n",
		    print_len, cname, start_blk, has_mddb_str,
		    col_state, devid, hsname, timep) == EOF) {
			goto out;
		}
	}

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (rval != 0)
		(void) mdsyserror(ep, errno, fname);

	return (rval);
}

/*
 * print raid options
 */
int
meta_print_raid_options(
	mdhspname_t	*hspnamep,
	char		*fname,
	FILE		*fp,
	md_error_t	*ep
)
{
	char		*hspname = ((hspnamep != NULL) ? hspnamep->hspname :
	    dgettext(TEXT_DOMAIN, "none"));
	int		rval = -1;

	/* print options */
	if (fprintf(fp, dgettext(TEXT_DOMAIN,
	    "    Hot spare pool: %s\n"), hspname) == EOF) {
		goto out;
	}

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (rval != 0)
		(void) mdsyserror(ep, errno, fname);
	return (rval);
}

/*
 * report raid
 */
static int
raid_report(
	mdsetname_t	*sp,
	md_raid_t	*raidp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	char		*p;
	uint_t		ncol = raidp->cols.cols_len;
	uint_t		orig_ncol = raidp->orig_ncol;
	diskaddr_t	column_size = raidp->column_size;
	char		*raid_state;
	md_timeval32_t	tv;
	char		*timep;
	uint_t		col;
	int		rval = -1;
	int		len = 0;
	uint_t		tstate = 0;

	if (options & PRINT_LARGEDEVICES) {
		if ((raidp->common.revision & MD_64BIT_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	if (options & PRINT_FN) {
		if ((raidp->common.revision & MD_FN_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	/* print header */
	if (options & PRINT_HEADER) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: RAID\n"),
		    raidp->common.namep->cname) == EOF) {
			goto out;
		}

	}

	/* print state */
	if (metaismeta(raidp->common.namep)) {
		if (meta_get_tstate(raidp->common.namep->dev, &tstate, ep) != 0)
			return (-1);
	}
	tstate &= MD_DEV_ERRORED; /* extract the errored tstate bits */
	raid_state = raid_state_to_name(raidp, &tv, tstate);
	if (options & PRINT_TIMES) {
		timep = meta_print_time(&tv);
	} else {
		timep = "";
	}

	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    State: %-12s %s\n"),
	    raid_state, timep) == EOF) {
		goto out;
	}

	/*
	 * Display recovery action if we're marked in the Unavailable state.
	 */
	if ((tstate == 0) || (tstate & MD_INACCESSIBLE)) {
		/* print what to do */
		if (tstate & MD_INACCESSIBLE) {
			char sname[MD_MAX_SETNAME + 3]; /* 3 = sizeof("-s ") */

			if (metaislocalset(sp)) {
				sname[0] = '\0';
			} else {
				(void) snprintf(sname, MD_MAX_SETNAME + 3,
				    "-s %s", sp->setname);
			}
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Invoke: metastat -i %s\n"), sname) == EOF) {
				goto out;
			}
		} else if ((p = raid_state_to_action(raidp)) != NULL) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Invoke: %s\n"), p) == EOF) {
				goto out;
			}
		}

		/* resync status */
		if (raidp->resync_flags & MD_RI_INPROGRESS) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync in progress: %2d.%1d%% done\n"),
			    raidp->percent_done/10,
			    raidp->percent_done % 10) == EOF) {
				goto out;
			}
		} else if (raidp->resync_flags & MD_GROW_INPROGRESS) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Initialization in progress: %2d.%1d%% "
			    "done\n"),
			    raidp->percent_done/10,
			    raidp->percent_done % 10) == EOF) {
				goto out;
			}
		} else if (raidp->state & RUS_REGEN) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Parity regeneration in progress: %2d.%1d%% "
			    "done\n"),
			    raidp->percent_done/10,
			    raidp->percent_done % 10) == EOF) {
				goto out;
			}
		}
	}

	/* print hotspare pool */
	if (raidp->hspnamep != NULL) {
		if (meta_print_raid_options(raidp->hspnamep,
		    fname, fp, ep) != 0) {
			return (-1);
		}
	}

	/* print interlace */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Interlace: %lld blocks\n"),
	    raidp->interlace) == EOF) {
		goto out;
	}

	/* print size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %lld blocks (%s)\n"),
	    raidp->common.size,
	    meta_number_to_string(raidp->common.size, DEV_BSIZE)) == EOF) {
		goto out;
	}

	/* MD_DEBUG stuff */
	if (options & PRINT_DEBUG) {
		mdname_t	*raidnp = raidp->common.namep;
		mr_unit_t	*mr;

		/* get additional info */
		if ((mr = (mr_unit_t *)meta_get_mdunit(sp, raidnp, ep)) == NULL)
			return (-1);
		assert(mr->c.un_type == MD_METARAID);

		/* print prewrite count and size */
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Prewrite Count: %u slots\n"),
		    mr->un_pwcnt) == EOF) {
			Free(mr);
			goto out;
		}
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Prewrite Slot Size: %u blocks\n"),
		    (mr->un_pwsize / mr->un_pwcnt)) == EOF) {
			Free(mr);
			goto out;
		}
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Prewrite Total Size: %u blocks\n"),
		    mr->un_pwsize) == EOF) {
			Free(mr);
			goto out;
		}
		Free(mr);
	}

	/* print original devices */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "Original device:\n")) == EOF)
		goto out;
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %lld blocks (%s)\n"),
	    column_size * (orig_ncol - 1),
	    meta_number_to_string(column_size * (orig_ncol - 1), DEV_BSIZE))
	    == EOF) {
		goto out;
	}
	/*
	 * Building a format string on the fly that will
	 * be used in (f)printf. This allows the length
	 * of the ctd to vary from small to large without
	 * looking horrible.
	 */
	for (col = 0; (col < orig_ncol); ++col) {
		len = max(len,
		    strlen(raidp->cols.cols_val[col].colnamep->cname));
	}

	len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
	len += 2;

	if (! (options & PRINT_TIMES)) {
		if (fprintf(fp,
		    "\t%-*.*s %-12.12s %-5.5s %12.12s %-5.5s  %s\n",
		    len, len,
		    dgettext(TEXT_DOMAIN, "Device"),
		    dgettext(TEXT_DOMAIN, "Start Block"),
		    dgettext(TEXT_DOMAIN, "Dbase"),
		    dgettext(TEXT_DOMAIN, "State"),
		    dgettext(TEXT_DOMAIN, "Reloc"),
		    dgettext(TEXT_DOMAIN, "Hot Spare")) == EOF) {
			goto out;
		}
	} else {
		if (fprintf(fp,
		    "\t%-*s  %5s  %-5s  %-11s  %-5s   %-9s  %s\n",
		    len,
		    dgettext(TEXT_DOMAIN, "Device"),
		    dgettext(TEXT_DOMAIN, "Start"),
		    dgettext(TEXT_DOMAIN, "Dbase"),
		    dgettext(TEXT_DOMAIN, "State"),
		    dgettext(TEXT_DOMAIN, "Reloc"),
		    dgettext(TEXT_DOMAIN, "Hot Spare"),
		    dgettext(TEXT_DOMAIN, "Time")) == EOF) {
			goto out;
		}
	}
	for (col = 0; (col < orig_ncol); ++col) {
		md_raidcol_t	*mdrcp = &raidp->cols.cols_val[col];

		if (display_raid_device_info(sp, mdrcp, fname, fp, options,
		    len, tstate, ep) != 0) {
			return (-1);
		}
	}

	/* print concatenated devices */
	if (col < ncol) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "Concatenated Devices:\n")) == EOF) {
			goto out;
		}
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Size: %lld blocks (%s)\n"),
		    column_size * (ncol - orig_ncol),
		    meta_number_to_string(column_size * (ncol - orig_ncol),
		    DEV_BSIZE))
		    == EOF) {
			goto out;
		}
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		if (! (options & PRINT_TIMES)) {
			if (fprintf(fp,
			    "\t%-*.*s %-12.12s %-5.5s %-12.12s %5.5s %s\n",
			    len, len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Start Block"),
			    dgettext(TEXT_DOMAIN, "Dbase"),
			    dgettext(TEXT_DOMAIN, "State"),
			    dgettext(TEXT_DOMAIN, "Reloc"),
			    dgettext(TEXT_DOMAIN, "Hot Spare")) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp,
			    "\t%-*s %5s %-5s %-11s %-9s %s\t%s\n",
			    len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Start"),
			    dgettext(TEXT_DOMAIN, "Dbase"),
			    dgettext(TEXT_DOMAIN, "State"),
			    dgettext(TEXT_DOMAIN, "Reloc"),
			    dgettext(TEXT_DOMAIN, "Hot Spare"),
			    dgettext(TEXT_DOMAIN, "Time")) == EOF) {
				goto out;
			}
		}
		assert(col == orig_ncol);
		for (/* void */; (col < ncol); col++) {
			md_raidcol_t	*mdrcp = &raidp->cols.cols_val[col];

			if (display_raid_device_info(sp, mdrcp, fname, fp,
			    options, len, tstate, ep) != 0) {
				return (-1);
			}
		}
	}

	/* add extra line */
	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (rval != 0)
		(void) mdsyserror(ep, errno, fname);
	return (rval);
}

/*
 * print/report raid
 */
int
meta_raid_print(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_raid_t	*raidp;
	int		col;

	/* should have same set */
	assert(sp != NULL);
	assert((raidnp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev))));

	/* print all raids */
	if (raidnp == NULL) {
		mdnamelist_t	*nlp = NULL;
		mdnamelist_t	*p;
		int		cnt;
		int		rval = 0;

		/* get list */
		if ((cnt = meta_get_raid_names(sp, &nlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recurse */
		for (p = nlp; (p != NULL); p = p->next) {
			mdname_t	*np = p->namep;

			if (meta_raid_print(sp, np, nlpp, fname, fp,
			    options, ep) != 0)
				rval = -1;
		}

		/* cleanup, return success */
		metafreenamelist(nlp);
		return (rval);
	}

	/* get unit structure */
	if ((raidp = meta_get_raid_common(sp, raidnp,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* check for parented */
	if ((! (options & PRINT_SUBDEVS)) &&
	    (MD_HAS_PARENT(raidp->common.parent))) {
		return (0);
	}

	/* print appropriate detail */
	if (options & PRINT_SHORT) {
		if (raid_print(raidp, fname, fp, options, ep) != 0)
			return (-1);
	} else {
		if (raid_report(sp, raidp, fname, fp, options, ep) != 0)
			return (-1);
	}

	/* Recurse on components that are metadevices */
	for (col = 0; col < raidp->cols.cols_len; ++col) {
		md_raidcol_t	*colp = &raidp->cols.cols_val[col];
		mdname_t	*namep = colp->colnamep;

		if ((metaismeta(namep)) &&
		    (meta_print_name(sp, namep, nlpp, fname, fp,
		    (options | PRINT_HEADER | PRINT_SUBDEVS),
		    NULL, ep) != 0)) {
			return (-1);
		}
	}

	return (0);
}

/*
 * adjust raid geometry
 */
static int
adjust_geom(
	mdname_t	*raidnp,
	mdname_t	*colnp,
	mr_unit_t	*mr,
	md_error_t	*ep
)
{
	uint_t		round_cyl = 1;
	mdgeom_t	*geomp;

	/* get reinstructs */
	if ((geomp = metagetgeom(colnp, ep)) == NULL)
		return (-1);

	/* adjust geometry */
	if (meta_adjust_geom((md_unit_t *)mr, raidnp, geomp->write_reinstruct,
	    geomp->read_reinstruct, round_cyl, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * add another column to the raid unit structure
 */
static int
attach_raid_col(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mr_unit_t	*mr,
	mr_column_t	*mdc,
	mdname_t	*colnp,
	rcs_state_t	state,
	mdnamelist_t	**keynlpp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	diskaddr_t	column_size = mr->un_segsize * mr->un_segsincolumn;
	diskaddr_t	size;
	uint_t		 maxio;
	mdcinfo_t	*cinfop;
	md_timeval32_t	tmp_time;

	/* setup state and timestamp */
	mdc->un_devstate = state;
	if (meta_gettimeofday(&tmp_time) == -1)
		return (mdsyserror(ep, errno, NULL));

	mdc->un_devtimestamp = tmp_time;
	/* get start, size, and maxio */
	if ((mdc->un_orig_devstart = metagetstart(sp, colnp, ep)) ==
	    MD_DISKADDR_ERROR)
		return (-1);
	if ((size = metagetsize(colnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((cinfop = metagetcinfo(colnp, ep)) == NULL)
		return (-1);
	maxio = cinfop->maxtransfer;

	/* adjust start and size by prewrite */
	mdc->un_orig_pwstart = mdc->un_orig_devstart;
	mdc->un_orig_devstart += mr->un_pwsize;

	/* make sure we still have something left */
	if ((mdc->un_orig_devstart >= size) ||
	    ((size - mdc->un_orig_devstart) < column_size)) {
		return (mdsyserror(ep, ENOSPC, colnp->cname));
	}
	size -= mdc->un_orig_devstart;
	if (maxio < mr->un_maxio) {
		return (mdcomperror(ep, MDE_MAXIO,
		    meta_getminor(raidnp->dev), colnp->dev, colnp->cname));
	}

	if (options & MDCMD_DOIT) {
		/* store name in namespace */
		if (add_key_name(sp, colnp, keynlpp, ep) != 0)
			return (-1);
	}

	/* setup column */
	mdc->un_orig_dev = colnp->dev;
	mdc->un_orig_key = colnp->key;
	mdc->un_dev = colnp->dev;
	mdc->un_pwstart = mdc->un_orig_pwstart;
	mdc->un_devstart = mdc->un_orig_devstart;
	mdc->un_alt_dev = NODEV64;
	mdc->un_alt_pwstart = 0;
	mdc->un_alt_devstart = 0;
	mdc->un_hs_id = 0;

	/* add the size (we use) of the device to the total */
	mr->c.un_actual_tb += column_size;

	/* adjust geometry */
	if (adjust_geom(raidnp, colnp, mr, ep) != 0)
		return (-1);

	/* count column */
	mr->un_totalcolumncnt++;

	/* return success */
	return (0);
}

/*
 * invalidate column names
 */
static int
invalidate_columns(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	md_error_t	*ep
)
{
	md_raid_t	*raidp;
	uint_t		col;

	if ((raidp = meta_get_raid(sp, raidnp, ep)) == NULL)
		return (-1);
	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;

		meta_invalidate_name(colnp);
	}
	return (0);
}

/*
 * attach columns to raid
 */
int
meta_raid_attach(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	mdnamelist_t		*colnlp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	uint_t			concat_cnt = 0;
	mdnamelist_t		*p;
	mr_unit_t		*old_mr;
	mr_unit_t		*new_mr;
	size_t			old_rusize;
	size_t			new_rusize;
	mdnamelist_t		*keynlp = NULL;
	md_grow_params_t	mgp;
	int			rval = -1;
	int			create_flag = MD_CRO_32BIT;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* check type */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* check and count new columns */
	for (p = colnlp; (p != NULL); p = p->next) {
		mdname_t	*np = p->namep;
		mdnamelist_t	*p2;

		/* check against existing devices */
		if (meta_check_column(sp, np, ep) != 0)
			return (-1);

		/* check against ourselves */
		for (p2 = p->next; (p2 != NULL); p2 = p2->next) {
			if (meta_check_overlap(np->cname, np, 0, -1,
			    p2->namep, 0, -1, ep) != 0) {
				return (-1);
			}
		}

		/* count */
		++concat_cnt;
	}

	/* get old unit */
	if ((old_mr = (mr_unit_t *)meta_get_mdunit(sp, raidnp, ep)) == NULL)
		return (-1);

	/*
	 * calculate the size needed for the new raid unit and allocate
	 * the appropriate structure. allocate new unit.
	 */
	old_rusize = sizeof (*old_mr) - sizeof (old_mr->un_column[0]);
	old_rusize += old_mr->un_totalcolumncnt * sizeof (old_mr->un_column[0]);
	new_rusize = sizeof (*new_mr) - sizeof (new_mr->un_column[0]);
	new_rusize += (old_mr->un_totalcolumncnt + concat_cnt)
	    * sizeof (new_mr->un_column[0]);
	new_mr = Zalloc(new_rusize);
	(void) memcpy(new_mr, old_mr, old_rusize);

	/* We always want a do-it, this is for attach_raid_col below */
	options |= MDCMD_DOIT;

	/* build new unit structure */
	for (p = colnlp; (p != NULL); p = p->next) {
		mdname_t	*colnp = p->namep;
		mr_column_t	*mdc;

		/* attach column */
		mdc = &new_mr->un_column[new_mr->un_totalcolumncnt];
		if (attach_raid_col(sp, raidnp, new_mr, mdc, colnp,
		    RCS_INIT, &keynlp, options, ep) != 0) {
			goto out;
		}
	}
	assert(new_mr->un_totalcolumncnt
	    == (old_mr->un_totalcolumncnt + concat_cnt));


	create_flag = meta_check_devicesize(new_mr->c.un_total_blocks);

	/* grow raid */
	(void) memset(&mgp, 0, sizeof (mgp));
	mgp.mnum = MD_SID(new_mr);
	MD_SETDRIVERNAME(&mgp, MD_RAID, sp->setno);
	mgp.size = new_rusize;
	mgp.mdp = (uintptr_t)new_mr;

	if (create_flag == MD_CRO_32BIT) {
		mgp.options = MD_CRO_32BIT;
		new_mr->c.un_revision &= ~MD_64BIT_META_DEV;
	} else {
		mgp.options = MD_CRO_64BIT;
		new_mr->c.un_revision |= MD_64BIT_META_DEV;
	}
	if (metaioctl(MD_IOCGROW, &mgp, &mgp.mde, NULL) != 0) {
		(void) mdstealerror(ep, &mgp.mde);
		goto out;
	}

	/* clear cache */
	if (invalidate_columns(sp, raidnp, ep) != 0)
		goto out;
	meta_invalidate_name(raidnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		if (concat_cnt == 1) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: component is attached\n"),
			    raidnp->cname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: components are attached\n"),
			    raidnp->cname);
		}
		(void) fflush(stdout);
	}


	/* grow any parents */
	if (meta_concat_parent(sp, raidnp, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* cleanup, return error */
out:
	Free(old_mr);
	Free(new_mr);
	if (rval != 0)
		(void) del_key_names(sp, keynlp, NULL);
	metafreenamelist(keynlp);
	return (rval);
}

/*
 * get raid parameters
 */
int
meta_raid_get_params(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mr_params_t	*paramsp,
	md_error_t	*ep
)
{
	md_raid_t	*raidp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* check name */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* get unit */
	if ((raidp = meta_get_raid(sp, raidnp, ep)) == NULL)
		return (-1);

	/* return parameters */
	(void) memset(paramsp, 0, sizeof (*paramsp));
	if (raidp->hspnamep == NULL)
		paramsp->hsp_id = MD_HSP_NONE;
	else
		paramsp->hsp_id = raidp->hspnamep->hsp;
	return (0);
}

/*
 * set raid parameters
 */
int
meta_raid_set_params(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	mr_params_t		*paramsp,
	md_error_t		*ep
)
{
	md_raid_params_t	msp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* check name */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* set parameters */
	(void) memset(&msp, 0, sizeof (msp));
	MD_SETDRIVERNAME(&msp, MD_RAID, sp->setno);
	msp.mnum = meta_getminor(raidnp->dev);
	msp.params = *paramsp;
	if (metaioctl(MD_IOCCHANGE, &msp, &msp.mde, raidnp->cname) != 0)
		return (mdstealerror(ep, &msp.mde));

	/* clear cache */
	meta_invalidate_name(raidnp);

	/* return success */
	return (0);
}

/*
 * validate raid replace column
 */
static int
validate_new_raid(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mdname_t	*colnp,
	replace_params_t *paramsp,
	int		dup_ok,
	md_error_t	*ep
)
{
	mr_unit_t	*mr;
	diskaddr_t	column_size;
	diskaddr_t	label;
	mdcinfo_t	*cinfop;
	int		rval = -1;

	/* get raid unit */
	if ((mr = (mr_unit_t *)meta_get_mdunit(sp, raidnp, ep)) == NULL)
		return (-1);
	column_size = mr->un_segsize * mr->un_segsincolumn;

	/* check it out */
	if (meta_check_column(sp, colnp, ep) != 0) {
		if ((! dup_ok) || (! mdisuseerror(ep, MDE_ALREADY)))
			goto out;
		mdclrerror(ep);
	}
	if ((paramsp->number_blks = metagetsize(colnp, ep)) ==
	    MD_DISKADDR_ERROR)
		goto out;
	if ((label = metagetlabel(colnp, ep)) == MD_DISKADDR_ERROR)
		goto out;
	paramsp->has_label = ((label > 0) ? 1 : 0);
	if ((paramsp->start_blk = metagetstart(sp, colnp, ep)) ==
	    MD_DISKADDR_ERROR)
		goto out;
	if ((paramsp->number_blks - paramsp->start_blk) < column_size) {
		(void) mdsyserror(ep, ENOSPC, colnp->cname);
		goto out;
	}
	if ((cinfop = metagetcinfo(colnp, ep)) == NULL)
		goto out;
	if (cinfop->maxtransfer < mr->un_maxio) {
		(void) mdcomperror(ep, MDE_MAXIO, meta_getminor(raidnp->dev),
		    colnp->dev, colnp->cname);
		goto out;
	}

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	Free(mr);
	return (rval);
}

/*
 * replace raid column
 */
int
meta_raid_replace(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	mdname_t		*oldnp,
	mdname_t		*newnp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	int			force = ((options & MDCMD_FORCE) ? 1 : 0);
	replace_params_t	params;
	md_dev64_t		old_dev, new_dev;
	diskaddr_t		new_start_blk, new_end_blk;
	int			rebind;
	char			*new_devidp = NULL;
	md_error_t		xep = mdnullerror;
	int			ret;
	md_set_desc		*sd;
	uint_t			tstate;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* check name */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* save new binding incase this is a rebind where oldnp==newnp */
	new_dev = newnp->dev;
	new_start_blk = newnp->start_blk;
	new_end_blk = newnp->end_blk;

	/* invalidate, then get the raid (fill in oldnp from metadb) */
	meta_invalidate_name(raidnp);
	if (meta_get_raid(sp, raidnp, ep) == NULL)
		return (-1);

	/* can't replace a component if the raid inaccessible */
	if (meta_get_tstate(raidnp->dev, &tstate, ep) != 0) {
		return (-1);
	}
	if (tstate & MD_INACCESSIBLE) {
		return (mdmderror(ep, MDE_IN_UNAVAIL_STATE,
		    meta_getminor(raidnp->dev), raidnp->cname));
	}

	/* the old device binding is now established */
	if ((old_dev = oldnp->dev) == NODEV64)
		return (mdsyserror(ep, ENODEV, oldnp->cname));


	/* setup raid info */
	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(raidnp->dev);
	MD_SETDRIVERNAME(&params, MD_RAID, sp->setno);
	params.old_dev = old_dev;
	params.cmd = force ? FORCE_REPLACE_COMP : REPLACE_COMP;

	if ((strcmp(oldnp->rname, newnp->rname) == 0) &&
	    (old_dev != new_dev)) {
		rebind = 1;
	} else {
		rebind = 0;
	}
	if (rebind) {
		newnp->dev = new_dev;
		newnp->start_blk = new_start_blk;
		newnp->end_blk = new_end_blk;
	}

	/*
	 * Save a copy of the devid associated with the new disk, the
	 * reason is that the checks for the column (meta_check_column)
	 * via validate_new_raid(), could cause the disk's devid to be
	 * changed to that of the devid that is currently stored in the
	 * replica namespace for the disk in question. This devid could
	 * be stale if we are replacing the disk. The actual function
	 * that overwrites the devid is dr2drivedesc().
	 */

	/* don't setup new_devid if no devid's or MN diskset */
	if (newnp->drivenamep->devid != NULL)
		new_devidp = Strdup(newnp->drivenamep->devid);

	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if (MD_MNSET_DESC(sd))
			new_devidp = NULL;
	}

	/* check out new (sets up start_blk, has_label, number_blks) */
	if (validate_new_raid(sp, raidnp, newnp, &params, rebind,
	    ep) != 0) {
		Free(new_devidp);
		return (-1);
	}

	/*
	 * Copy back the saved devid.
	 */
	Free(newnp->drivenamep->devid);
	if (new_devidp) {
		newnp->drivenamep->devid = Strdup(new_devidp);
		Free(new_devidp);
	}

	/* store name in namespace, allocate new key */
	if (add_key_name(sp, newnp, NULL, ep) != 0)
		return (-1);

	if (rebind && !metaislocalset(sp)) {
		/*
		 * We are 'rebind'ing a disk that is in a diskset so as well
		 * as updating the diskset's namespace the local set needs
		 * to be updated because it also contains a reference to the
		 * disk in question.
		 */
		ret = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET,
		    newnp->cname, ep);

		if (ret != METADEVADM_SUCCESS) {
			(void) del_key_name(sp, newnp, &xep);
			return (-1);
		}
	}

	/* replace column */
	params.new_dev = new_dev;
	params.new_key = newnp->key;
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0) {
		(void) del_key_name(sp, newnp, ep);
		return (mdstealerror(ep, &params.mde));
	}

	/* clear cache */
	meta_invalidate_name(oldnp);
	meta_invalidate_name(newnp);
	meta_invalidate_name(raidnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is replaced with %s\n"),
		    raidnp->cname, oldnp->cname, newnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * enable raid column
 */
int
meta_raid_enable(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	mdname_t		*colnp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	int			force = ((options & MDCMD_FORCE) ? 1 : 0);
	replace_params_t	params;
	md_dev64_t		fs_dev, del_dev;
	int			err = 0;
	char			*devnm;
	int			ret;
	uint_t			tstate;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* check name */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* get the file_system dev binding */
	if (meta_getdev(sp, colnp, ep) != 0)
		return (-1);
	fs_dev = colnp->dev;

	/* get the raid unit (fill in colnp->dev with metadb version) */
	meta_invalidate_name(raidnp);
	if (meta_get_raid(sp, raidnp, ep) == NULL)
		return (-1);

	/* enabling a component can't work if the raid inaccessible */
	if (meta_get_tstate(raidnp->dev, &tstate, ep) != 0) {
		return (-1);
	}
	if (tstate & MD_INACCESSIBLE) {
		return (mdmderror(ep, MDE_IN_UNAVAIL_STATE,
		    meta_getminor(raidnp->dev), raidnp->cname));
	}

	/* the metadb device binding is now established */
	if (colnp->dev == NODEV64)
		return (mdsyserror(ep, ENODEV, colnp->cname));

	/*
	 * check for the case where the dev_t has changed between the
	 * filesystem and the metadb.  This is called a rebind, and
	 * is handled by meta_raid_replace.
	 */
	if (fs_dev != colnp->dev) {
		/*
		 * Save the devt of mddb version
		 */
		del_dev = colnp->dev;

		/* establish file system binding with invalid start/end */
		colnp->dev = fs_dev;
		colnp->start_blk = -1;
		colnp->end_blk = -1;
		err = meta_raid_replace(sp, raidnp, colnp, colnp, options, ep);

		/*
		 * Don't do it if meta_raid_replace returns an error
		 */
		if (!err && (devnm = meta_getnmentbydev(sp->setno, MD_SIDEWILD,
		    del_dev, NULL, NULL, &colnp->key, ep)) != NULL) {
			(void) del_key_name(sp, colnp, ep);
			Free(devnm);
		}
		return (err);
	}

	/* setup raid info */
	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(raidnp->dev);
	MD_SETDRIVERNAME(&params, MD_RAID, sp->setno);
	params.old_dev = params.new_dev = colnp->dev;
	if (force)
		params.cmd = FORCE_ENABLE_COMP;
	else
		params.cmd = ENABLE_COMP;

	/* check it out */
	if (validate_new_raid(sp, raidnp, colnp, &params, 1, ep) != 0)
		return (-1);

	/* enable column */
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0)
		return (mdstealerror(ep, &params.mde));

	/*
	 * are we dealing with a non-local set? If so need to update the
	 * local namespace so that the disk record has the correct devid.
	 */
	if (!metaislocalset(sp)) {
		ret = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET, colnp->cname,
		    ep);

		if (ret != METADEVADM_SUCCESS) {
			/*
			 * Failed to update the local set. Nothing to do here
			 * apart from report the error. The namespace is
			 * most likely broken and some form of remedial
			 * recovery is going to be required.
			 */
			mde_perror(ep, "");
			mdclrerror(ep);
		}
	}

	/* clear cache */
	meta_invalidate_name(colnp);
	meta_invalidate_name(raidnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is enabled\n"),
		    raidnp->cname, colnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * check for dups in the raid itself
 */
static int
check_twice(
	md_raid_t	*raidp,
	uint_t		col,
	md_error_t	*ep
)
{
	mdname_t	*raidnp = raidp->common.namep;
	mdname_t	*thisnp;
	uint_t		c;

	thisnp = raidp->cols.cols_val[col].colnamep;
	for (c = 0; (c < col); ++c) {
		md_raidcol_t	*mdcp = &raidp->cols.cols_val[c];
		mdname_t	*colnp = mdcp->colnamep;

		if (meta_check_overlap(raidnp->cname, thisnp, 0, -1,
		    colnp, 0, -1, ep) != 0) {
			return (-1);
		}
	}
	return (0);
}

/*
 * default raid interlace
 */
diskaddr_t
meta_default_raid_interlace(void)
{
	diskaddr_t	interlace;

	/* default to 512k, round up if necessary */
	interlace = btodb(512 * 1024);
	if (interlace < lbtodb(MININTERLACE))
		interlace = roundup(MININTERLACE, interlace);
	return (interlace);
}

/*
 * convert interlaces
 */
int
meta_raid_check_interlace(
	diskaddr_t	interlace,
	char		*uname,
	md_error_t	*ep
)
{
	if ((interlace < btodb(RAID_MIN_INTERLACE)) ||
	    (interlace > btodb(MAXINTERLACE))) {
		return (mderror(ep, MDE_BAD_INTERLACE, uname));
	}
	return (0);
}

/*
 * check raid
 */
int
meta_check_raid(
	mdsetname_t	*sp,
	md_raid_t	*raidp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*raidnp = raidp->common.namep;
	int		doit = ((options & MDCMD_DOIT) ? 1 : 0);
	int		updateit = ((options & MDCMD_UPDATE) ? 1 : 0);
	uint_t		ncol;
	uint_t		col;
	minor_t		mnum = meta_getminor(raidnp->dev);

	/* check number */
	if (((ncol = raidp->cols.cols_len) < MD_RAID_MIN) ||
	    (raidp->orig_ncol > ncol)) {
		return (mdmderror(ep, MDE_BAD_RAID, mnum, raidnp->cname));
	}

	/* compute default interlace */
	if (raidp->interlace == 0) {
		raidp->interlace = meta_default_raid_interlace();
	}

	/* check state */
	switch (raidp->state) {
	case RUS_INIT:
	case RUS_OKAY:
		break;

	default:
		return (mdmderror(ep, MDE_BAD_RAID, mnum, raidnp->cname));
	}

	/* check interlace */
	if (meta_raid_check_interlace(raidp->interlace, raidnp->cname, ep) != 0)
		return (-1);

	/* check hotspare pool name */
	if (doit) {
		if ((raidp->hspnamep != NULL) &&
		    (metachkhsp(sp, raidp->hspnamep, ep) != 0)) {
			return (-1);
		}
	}

	/* check columns */
	for (col = 0; (col < ncol); ++col) {
		md_raidcol_t	*mdcp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = mdcp->colnamep;
		diskaddr_t	start_blk, size;

		/* setup column */
		if (raidp->state == RUS_INIT)
			mdcp->state = RCS_INIT;
		else
			mdcp->state = RCS_OKAY;

		/* check column */
		if (!updateit) {
			if (meta_check_column(sp, colnp, ep) != 0)
				return (-1);
			if (((start_blk = metagetstart(sp, colnp, ep)) ==
			    MD_DISKADDR_ERROR) || ((size = metagetsize(colnp,
			    ep)) == MD_DISKADDR_ERROR)) {
				return (-1);
			}
			if (start_blk >= size)
				return (mdsyserror(ep, ENOSPC, colnp->cname));
			size -= start_blk;
			size = rounddown(size, raidp->interlace);
			if (size == 0)
				return (mdsyserror(ep, ENOSPC, colnp->cname));
		}

		/* check this raid too */
		if (check_twice(raidp, col, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * setup raid geometry
 */
static int
raid_geom(
	md_raid_t	*raidp,
	mr_unit_t	*mr,
	md_error_t	*ep
)
{
	uint_t		write_reinstruct = 0;
	uint_t		read_reinstruct = 0;
	uint_t		round_cyl = 1;
	uint_t		col;
	mdgeom_t	*geomp;

	/* get worst reinstructs */
	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*mdcp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = mdcp->colnamep;

		if ((geomp = metagetgeom(colnp, ep)) == NULL)
			return (-1);
		if (geomp->write_reinstruct > write_reinstruct)
			write_reinstruct = geomp->write_reinstruct;
		if (geomp->read_reinstruct > read_reinstruct)
			read_reinstruct = geomp->read_reinstruct;
	}

	/* setup geometry from first column */
	assert(raidp->cols.cols_len > 0);
	if ((geomp = metagetgeom(raidp->cols.cols_val[0].colnamep,
	    ep)) == NULL) {
		return (-1);
	}
	if (meta_setup_geom((md_unit_t *)mr, raidp->common.namep, geomp,
	    write_reinstruct, read_reinstruct, round_cyl, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

int
meta_raid_state_cnt(mr_unit_t *mr, rcs_state_t state)
{
	int 	statecnt = 0;
	int	col;

	for (col = 0; col < mr->un_totalcolumncnt; col++)
		if (mr->un_column[col].un_devstate & state)
			statecnt++;
	return (statecnt);
}
/*
 * validate that a raid device being created with the -k flag is a real
 * raid device
 */
int
meta_raid_valid(md_raid_t *raidp, mr_unit_t *mr)
{
	long long	buf[DEV_BSIZE / sizeof (long long)];
	raid_pwhdr_t	pwhdr;
	raid_pwhdr_t	*rpw = &pwhdr;
	minor_t		mnum;
	int		col;
	int		fd;

	for (col = 0; col < mr->un_totalcolumncnt; col++) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;

		if ((fd = open(colnp->rname, O_RDONLY)) < 0)
			goto error_exit;

		if (lseek64(fd,
		    (mr->un_column[col].un_pwstart * DEV_BSIZE), SEEK_SET) < 0)
			goto error_exit;

		if (read(fd, buf, DEV_BSIZE) < 0)
			goto error_exit;

		/*
		 * If our raid device is a 64 bit device, we can accept the
		 * pw header we just read in.
		 * Otherwise it's of type raid_pwhdr32_od_t and has to
		 * be converted.
		 */
		if (mr->c.un_revision & MD_64BIT_META_DEV) {
			rpw = (raid_pwhdr_t *)buf;
		} else {
			RAID_CONVERT_RPW((raid_pwhdr32_od_t *)buf, rpw);
		}

		if (rpw->rpw_column != col)
			goto error_exit;

		if (col == 0)
			mnum = rpw->rpw_unit;

		if (rpw->rpw_unit != mnum)
			goto error_exit;

		if (rpw->rpw_magic_ext == RAID_PWMAGIC) {
			/* 4.1 prewrite header */
			if ((rpw->rpw_origcolumncnt != mr->un_origcolumncnt) ||
			    (rpw->rpw_totalcolumncnt !=
			    mr->un_totalcolumncnt) ||
			    (rpw->rpw_segsize != mr->un_segsize) ||
			    (rpw->rpw_segsincolumn != mr->un_segsincolumn) ||
			    (rpw->rpw_pwcnt != mr->un_pwcnt) ||
			    (rpw->rpw_pwstart !=
			    mr->un_column[col].un_pwstart) ||
			    (rpw->rpw_devstart !=
			    mr->un_column[col].un_devstart) ||
			    (rpw->rpw_pwsize != mr->un_pwsize))
				goto error_exit;
		}
		/*
		 * this is an old prewrite header (4.0) the unit structure
		 * will have to be trusted.
		 */
		(void) close(fd);
	}

	return (0);

error_exit:
	(void) close(fd);
	return (-1);
}

/*
 * create raid
 */
int
meta_create_raid(
	mdsetname_t	*sp,
	md_raid_t	*raidp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*raidnp = raidp->common.namep;
	uint_t		ncol = raidp->cols.cols_len;
	uint_t		orig_ncol = raidp->orig_ncol;
	size_t		rdsize;
	mr_unit_t	*mr;
	uint_t		col;
	diskaddr_t	disk_size = 0;
	uint_t		disk_maxio = 0;
	uint_t		pwes;
	diskaddr_t	non_pw_blks, column_size;
	mdnamelist_t	*keynlp = NULL;
	md_set_params_t	set_params;
	int		rval = -1;
	md_timeval32_t	creation_time;
	int		create_flag = MD_CRO_32BIT;

	/* validate raid */
	if (meta_check_raid(sp, raidp, options, ep) != 0)
		return (-1);

	/* allocate raid unit */
	rdsize = sizeof (*mr) - sizeof (mr->un_column[0]);
	rdsize += ncol * sizeof (mr->un_column[0]);
	mr = Zalloc(rdsize);

	if (meta_gettimeofday(&creation_time) == -1)
		return (mdsyserror(ep, errno, NULL));
	/*
	 * initialize the top level mr_unit_t structure
	 * setup the unit state to indicate whether to retain
	 * any data currently on the metadevice or to clear it
	 */
	mr->c.un_type = MD_METARAID;
	MD_SID(mr) = meta_getminor(raidnp->dev);
	mr->c.un_size = rdsize;
	mr->un_magic = RAID_UNMAGIC;
	mr->un_state = raidp->state;
	mr->un_timestamp = creation_time;
	mr->un_origcolumncnt = orig_ncol;
	mr->un_segsize = (uint_t)raidp->interlace;
	if (raidp->hspnamep != NULL) {
		mr->un_hsp_id = raidp->hspnamep->hsp;
	} else {
		mr->un_hsp_id = MD_HSP_NONE;
	}
	/*
	 * setup original columns, saving start_block and
	 * finding smallest size and maxio
	 */
	for (col = 0; (col < orig_ncol); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;
		mr_column_t	*mdc = &mr->un_column[col];
		diskaddr_t	size;
		uint_t		maxio;
		mdcinfo_t	*cinfop;

		/* setup state */
		mdc->un_devstate = cp->state;

		/* setup creation time */
		mdc->un_devtimestamp = creation_time;

		/* get start, size, and maxio */
		if ((mdc->un_orig_devstart = metagetstart(sp, colnp, ep)) ==
		    MD_DISKADDR_ERROR)
			goto out;
		if ((size = metagetsize(colnp, ep)) == MD_DISKADDR_ERROR)
			goto out;
		size -= mdc->un_orig_devstart;
		if ((cinfop = metagetcinfo(colnp, ep)) == NULL)
			goto out;
		maxio = cinfop->maxtransfer;

		if (options & MDCMD_DOIT) {
			/* store name in namespace */
			if (add_key_name(sp, colnp, &keynlp, ep) != 0)
				goto out;
		}

		/* setup column */
		mdc->un_orig_key = colnp->key;
		mdc->un_orig_dev = colnp->dev;
		mdc->un_dev = mdc->un_orig_dev;
		mdc->un_pwstart = mdc->un_orig_pwstart;
		mdc->un_devstart = mdc->un_orig_devstart;
		mdc->un_alt_dev = NODEV64;
		mdc->un_alt_pwstart = 0;
		mdc->un_alt_devstart = 0;
		mdc->un_hs_id = 0;
		if (mr->un_state == RUS_INIT)
			mdc->un_devstate = RCS_INIT;
		else
			mdc->un_devstate = RCS_OKAY;

		/* adjust for smallest disk */
		if (disk_size == 0) {
			disk_size = size;
		} else if (size < disk_size) {
			disk_size = size;
		}
		if (disk_maxio == 0) {
			disk_maxio = maxio;
		} else if (maxio < disk_maxio) {
			disk_maxio = maxio;
		}
	}
	assert(col == mr->un_origcolumncnt);

	/*
	 * before processing any of the attached column(s)
	 * set up the composition of the metadevice for column
	 * sizes and pre-write information
	 */
	mr->un_maxio = disk_maxio;	/* smallest maxio */
	mr->un_iosize = min(mr->un_maxio, (mr->un_segsize + 1));
	pwes = mr->un_iosize;
	if (raidp->pw_count)
		mr->un_pwcnt = raidp->pw_count;
	else
		mr->un_pwcnt = PWCNT_MIN;
	if ((mr->un_pwcnt < PWCNT_MIN) || (mr->un_pwcnt > PWCNT_MAX)) {
		(void) mderror(ep, MDE_RAID_BAD_PW_CNT, raidnp->cname);
		goto out;
	}
	mr->un_pwsize = roundup((mr->un_pwcnt * pwes), 2);

	/* now calculate the number of segments per column */
	non_pw_blks = disk_size - mr->un_pwsize;	/* smallest disk */
	if ((mr->un_pwsize > disk_size) ||
	    (non_pw_blks < (diskaddr_t)mr->un_segsize)) {
		(void) mdsyserror(ep, ENOSPC, raidnp->cname);
		goto out;
	}
	mr->un_segsincolumn = non_pw_blks / mr->un_segsize;
	column_size = mr->un_segsize * mr->un_segsincolumn;

	/*
	 * adjust the pw_cnt, pw_size, to fit into any fragmentation
	 * left over after column_size has been computed
	 */
	mr->un_pwsize = rounddown(((uint_t)(disk_size - column_size)), 2);
	mr->un_pwcnt = mr->un_pwsize / pwes;
	assert(mr->un_pwcnt >= PWCNT_MIN);
	mr->un_pwsize = roundup((mr->un_pwcnt * pwes), 2);
	assert((mr->un_pwsize + column_size) <= disk_size);

	/*
	 * calculate the actual block count available based on the
	 * segment size and the number of segments per column ...
	 * ... and adjust for the number of parity segments
	 */
	mr->c.un_actual_tb = column_size * (mr->un_origcolumncnt - 1);

	if (raid_geom(raidp, mr, ep) != 0)
		goto out;

	create_flag = meta_check_devicesize(mr->c.un_total_blocks);

	/*
	 * now calculate the pre-write offset and update the column
	 * structures to include the address of the individual pre-write
	 * areas
	 */
	for (col = 0; (col < orig_ncol); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;
		mr_column_t	*mdc = &mr->un_column[col];
		diskaddr_t	size;

		/* get size */
		if ((size = metagetsize(colnp, ep)) == MD_DISKADDR_ERROR)
			goto out;

		/* adjust start and size by prewrite */
		mdc->un_orig_pwstart = mdc->un_orig_devstart;
		mdc->un_orig_devstart += mr->un_pwsize;
		mdc->un_pwstart = mdc->un_orig_pwstart;
		mdc->un_devstart = mdc->un_orig_devstart;

		assert(size >= mdc->un_orig_devstart);
		size -= mdc->un_orig_devstart;

		/* make sure we still have something left */
		assert(size >= column_size);
	}

	/* do concat cols */
	mr->un_totalcolumncnt = mr->un_origcolumncnt;
	assert(col == mr->un_origcolumncnt);
	for (col = orig_ncol; (col < ncol); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;
		mr_column_t	*mdc = &mr->un_column[col];

		/* attach column */
		if (attach_raid_col(sp, raidnp, mr, mdc, colnp,
		    cp->state, &keynlp, options, ep) != 0) {
			goto out;
		}
	}
	assert(mr->un_totalcolumncnt == ncol);

	/* fill in the size of the raid */
	if (options & MDCMD_UPDATE) {
		raidp->common.size = mr->c.un_total_blocks;
		raidp->column_size = mr->un_segsize * mr->un_segsincolumn;
	}

	/* if we're not doing anything, return success */
	if (! (options & MDCMD_DOIT)) {
		rval = 0;	/* success */
		goto out;
	}

	if ((mr->un_state & RUS_OKAY) &&
	    (meta_raid_valid(raidp, mr) != 0)) {
		(void) mderror(ep, MDE_RAID_INVALID, raidnp->cname);
		goto out;
	}

	/* create raid */
	(void) memset(&set_params, 0, sizeof (set_params));
	/* did the user tell us to generate a large device? */
	if (create_flag == MD_CRO_64BIT) {
		mr->c.un_revision |= MD_64BIT_META_DEV;
		set_params.options = MD_CRO_64BIT;
	} else {
		mr->c.un_revision &= ~MD_64BIT_META_DEV;
		set_params.options = MD_CRO_32BIT;
	}
	set_params.mnum = MD_SID(mr);
	set_params.size = mr->c.un_size;
	set_params.mdp = (uintptr_t)mr;
	MD_SETDRIVERNAME(&set_params, MD_RAID, MD_MIN2SET(set_params.mnum));
	if (metaioctl(MD_IOCSET, &set_params, &set_params.mde,
	    raidnp->cname) != 0) {
		(void) mdstealerror(ep, &set_params.mde);
		goto out;
	}
	rval = 0;	/* success */

	/* cleanup, return success */
out:
	Free(mr);
	if (rval != 0) {
		(void) del_key_names(sp, keynlp, NULL);
	}
	metafreenamelist(keynlp);
	if ((rval == 0) && (options & MDCMD_DOIT)) {
		if (invalidate_columns(sp, raidnp, ep) != 0)
			rval = -1;
		meta_invalidate_name(raidnp);
	}
	return (rval);
}

/*
 * initialize raid
 * NOTE: this functions is metainit(1m)'s command line parser!
 */
int
meta_init_raid(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*uname = argv[0];
	mdname_t	*raidnp = NULL;
	int		old_optind;
	int		c;
	md_raid_t	*raidp = NULL;
	uint_t		ncol, col;
	int		rval = -1;
	md_set_desc	*sd;

	/* get raid name */
	assert(argc > 0);
	if (argc < 1)
		goto syntax;
	if ((raidnp = metaname(spp, uname, META_DEVICE, ep)) == NULL)
		goto out;
	assert(*spp != NULL);

	/*
	 * Raid metadevice not allowed on multi-node diskset.
	 */
	if (! metaislocalset(*spp)) {
		if ((sd = metaget_setdesc(*spp, ep)) == NULL)
			goto out;
		if (MD_MNSET_DESC(sd)) {
			rval = meta_cook_syntax(ep, MDE_MNSET_NORAID, uname,
			    argc, argv);
			goto out;
		}
	}

	uname = raidnp->cname;
	if (metachkmeta(raidnp, ep) != 0)
		goto out;

	if (!(options & MDCMD_NOLOCK)) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep) != 0)
			goto out;

		if (meta_check_ownership(*spp, ep) != 0)
			goto out;
	}

	/* see if it exists already */
	if (metagetmiscname(raidnp, ep) != NULL) {
		(void) mdmderror(ep, MDE_UNIT_ALREADY_SETUP,
		    meta_getminor(raidnp->dev), uname);
		goto out;
	} else if (! mdismderror(ep, MDE_UNIT_NOT_SETUP)) {
		goto out;
	} else {
		mdclrerror(ep);
	}
	--argc, ++argv;

	/* grab -r */
	if ((argc < 1) || (strcmp(argv[0], "-r") != 0))
		goto syntax;
	--argc, ++argv;

	/* parse general options */
	optind = 0;
	opterr = 0;
	if (getopt(argc, argv, "") != -1)
		goto options;

	/* allocate raid */
	raidp = Zalloc(sizeof (*raidp));

	/* setup common */
	raidp->common.namep = raidnp;
	raidp->common.type = MD_METARAID;
	raidp->state = RUS_INIT;

	/* allocate and parse cols */
	for (ncol = 0; ((ncol < argc) && (argv[ncol][0] != '-')); ++ncol)
		;
	raidp->cols.cols_len = ncol;
	if (ncol != 0) {
		raidp->cols.cols_val =
		    Zalloc(ncol * sizeof (*raidp->cols.cols_val));
	}
	for (col = 0; ((argc > 0) && (col < ncol)); ++col) {
		md_raidcol_t	*mdc = &raidp->cols.cols_val[col];
		mdname_t	*colnp;

		/* parse column name */
		if ((colnp = metaname(spp, argv[0], UNKNOWN, ep)) == NULL)
			goto out;
		/* check for soft partitions */
		if (meta_sp_issp(*spp, colnp, ep) != 0) {
			/* check disks */
			if (metachkcomp(colnp, ep) != 0)
				goto out;
		}
		mdc->colnamep = colnp;
		--argc, ++argv;
	}

	/* parse raid options */
	old_optind = optind = 0;
	opterr = 0;
	while ((c = getopt(argc, argv, "h:i:ko:w:")) != -1) {
		switch (c) {
		case 'h':
			if ((raidp->hspnamep = metahspname(spp, optarg,
			    ep)) == NULL) {
				goto out;
			}

			/*
			 * Get out if the specified hotspare pool really
			 * doesn't exist.
			 */
			if (raidp->hspnamep->hsp == MD_HSP_NONE) {
				(void) mdhsperror(ep, MDE_INVAL_HSP,
				    raidp->hspnamep->hsp, optarg);
				goto out;
			}
			break;

		case 'i':
			if (parse_interlace(uname, optarg, &raidp->interlace,
			    ep) != 0) {
				goto out;
			}
			if (meta_raid_check_interlace(raidp->interlace,
			    uname, ep))
				goto out;
			break;

		case 'k':
			raidp->state = RUS_OKAY;
			break;

		case 'o':
			if ((sscanf(optarg, "%u", &raidp->orig_ncol) != 1) ||
			    ((int)raidp->orig_ncol < 0)) {
				goto syntax;
			}
			if ((raidp->orig_ncol < MD_RAID_MIN) ||
			    (raidp->orig_ncol > ncol)) {
				rval = mderror(ep, MDE_BAD_ORIG_NCOL, uname);
				goto out;
			}
			break;
		case 'w':
			if ((sscanf(optarg, "%d", &raidp->pw_count) != 1) ||
			    ((int)raidp->pw_count < 0))
				goto syntax;
			if (((int)raidp->pw_count < PWCNT_MIN) ||
			    ((int)raidp->pw_count > PWCNT_MAX)) {
				rval = mderror(ep, MDE_RAID_BAD_PW_CNT, uname);
				goto out;
			}
			break;
		default:
			argc += old_optind;
			argv -= old_optind;
			goto options;
		}
		old_optind = optind;
	}
	argc -= optind;
	argv += optind;

	/* we should be at the end */
	if (argc != 0)
		goto syntax;

	/* default to all original columns */
	if (raidp->orig_ncol == 0)
		raidp->orig_ncol = ncol;

	/* create raid */
	if (meta_create_raid(*spp, raidp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN, "%s: RAID is setup\n"),
		    uname);
		(void) fflush(stdout);
	}
	goto out;

	/* syntax error */
syntax:
	rval = meta_cook_syntax(ep, MDE_SYNTAX, uname, argc, argv);
	goto out;

	/* options error */
options:
	rval = meta_cook_syntax(ep, MDE_OPTION, uname, argc, argv);
	goto out;

	/* cleanup, return error */
out:
	if (raidp != NULL)
		meta_free_raid(raidp);
	return (rval);
}

/*
 * reset RAIDs
 */
int
meta_raid_reset(
	mdsetname_t	*sp,
	mdname_t	*raidnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_raid_t	*raidp;
	int		rval = -1;
	int		col;

	/* should have same set */
	assert(sp != NULL);
	assert((raidnp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev))));

	/* reset all raids */
	if (raidnp == NULL) {
		mdnamelist_t	*raidnlp = NULL;
		mdnamelist_t	*p;

		/* for each raid */
		rval = 0;
		if (meta_get_raid_names(sp, &raidnlp, 0, ep) < 0)
			return (-1);
		for (p = raidnlp; (p != NULL); p = p->next) {
			/* reset RAID */
			raidnp = p->namep;
			if (meta_raid_reset(sp, raidnp, options, ep) != 0) {
				rval = -1;
				break;
			}
		}

		/* cleanup, return success */
		metafreenamelist(raidnlp);
		return (rval);
	}

	/* check name */
	if (metachkmeta(raidnp, ep) != 0)
		return (-1);

	/* get unit structure */
	if ((raidp = meta_get_raid(sp, raidnp, ep)) == NULL)
		return (-1);

	/* make sure nobody owns us */
	if (MD_HAS_PARENT(raidp->common.parent)) {
		return (mdmderror(ep, MDE_IN_USE, meta_getminor(raidnp->dev),
		    raidnp->cname));
	}

	/* clear subdevices cache */
	if (invalidate_columns(sp, raidnp, ep) != 0)
		return (-1);

	/* clear metadevice */
	if (meta_reset(sp, raidnp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN, "%s: RAID is cleared\n"),
		    raidnp->cname);
		(void) fflush(stdout);
	}

	/* clear subdevices */
	if (! (options & MDCMD_RECURSE))
		goto out;

	for (col = 0; (col < raidp->cols.cols_len); ++col) {
		md_raidcol_t	*cp = &raidp->cols.cols_val[col];
		mdname_t	*colnp = cp->colnamep;

		/* only recurse on metadevices */
		if (! metaismeta(colnp))
			continue;

		if (meta_reset_by_name(sp, colnp, options, ep) != 0)
			rval = -1;
	}

	/* cleanup, return success */
out:
	meta_invalidate_name(raidnp);
	return (rval);
}

/*
 * reports TRUE if any RAID component is in error
 */
int
meta_raid_anycomp_is_err(mdsetname_t *sp, mdnamelist_t *raid_names)
{
	mdnamelist_t	*nlp;
	md_error_t	  status	= mdnullerror;
	md_error_t	 *ep		= &status;
	int		  any_errs	= FALSE;

	for (nlp = raid_names; nlp; nlp = nlp->next) {
		md_raid_t	*raidp;

		if ((raidp = meta_get_raid(sp, nlp->namep, ep)) == NULL) {
			any_errs |= TRUE;
			goto out;
		}
		if (raidp->state != RUS_OKAY && raidp->state != RUS_INIT) {
			any_errs |= TRUE;
			goto out;
		}
	}
out:
	if (!mdisok(ep))
		mdclrerror(ep);

	return (any_errs);
}
/*
 * regen parity on a raid
 */
int
meta_raid_regen_byname(mdsetname_t *sp, mdname_t *raidnp, diskaddr_t size,
	md_error_t *ep)
{
	char			*miscname;
	md_resync_ioctl_t	ri;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* make sure we have a raid */
	if ((miscname = metagetmiscname(raidnp, ep)) == NULL)
		return (-1);
	if (strcmp(miscname, MD_RAID) != 0) {
		return (mdmderror(ep, MDE_NOT_RAID, meta_getminor(raidnp->dev),
		    raidnp->cname));
	}

	/* start resync */
	(void) memset(&ri, 0, sizeof (ri));
	MD_SETDRIVERNAME(&ri, MD_RAID, sp->setno);
	ri.ri_mnum = meta_getminor(raidnp->dev);
	ri.ri_copysize = size;
	if (metaioctl(MD_IOCSETREGEN, &ri, &ri.mde, raidnp->cname) != 0)
		return (mdstealerror(ep, &ri.mde));

	/* return success */
	return (0);
}

int
meta_raid_check_component(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_dev64_t	mydevs,
	md_error_t	*ep
)
{
	md_raid_t	 *raid;
	mdnm_params_t	nm;
	md_getdevs_params_t	mgd;
	side_t	sideno;
	char	*miscname;
	md_dev64_t	*mydev = NULL;
	mdkey_t	key;
	char	*pname, *t;
	char	*ctd_name;
	char	*devname;
	int	len;
	int	i;
	int	rval = -1;

	(void) memset(&nm, '\0', sizeof (nm));
	if ((raid = meta_get_raid_common(sp, np, 0, ep)) == NULL)
		return (-1);

	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);

	sideno = getmyside(sp, ep);

	/* get count of underlying devices */

	(void) memset(&mgd, '\0', sizeof (mgd));
	MD_SETDRIVERNAME(&mgd, miscname, sp->setno);
	mgd.mnum = meta_getminor(np->dev);
	mgd.cnt = 0;
	mgd.devs = NULL;
	if (metaioctl(MD_IOCGET_DEVS, &mgd, &mgd.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &mgd.mde);
		rval = 0;
		goto out;
	} else if (mgd.cnt <= 0) {
		assert(mgd.cnt >= 0);
		rval = 0;
		goto out;
	}

	/*
	 * Now get the data from the unit structure.
	 * The compnamep stuff contains the data from
	 * the namespace and we need the un_dev
	 * from the unit structure.
	 */
	mydev = Zalloc(sizeof (*mydev) * mgd.cnt);
	mgd.devs = (uintptr_t)mydev;
	if (metaioctl(MD_IOCGET_DEVS, &mgd, &mgd.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &mgd.mde);
		rval = 0;
		goto out;
	} else if (mgd.cnt <= 0) {
		assert(mgd.cnt >= 0);
		rval = 0;
		goto out;
	}

	for (i = 0; i < raid->orig_ncol; i++) {
		md_raidcol_t	*colp = &raid->cols.cols_val[i];
		mdname_t	*compnp = colp->colnamep;

		if (mydevs == mydev[i]) {
			/* Get the devname from the name space. */
			if ((devname = meta_getnmentbydev(sp->setno, sideno,
			    compnp->dev, NULL, NULL, &key, ep)) == NULL) {
				goto out;
			}

			if (compnp->dev != meta_getminor(mydev[i])) {
				/*
				 * The minor numbers are different. Update
				 * the namespace with the information from
				 * the component.
				 */

				t = strrchr(devname, '/');
				t++;
				ctd_name = Strdup(t);

				len = strlen(devname);
				t = strrchr(devname, '/');
				t++;
				pname = Zalloc((len - strlen(t)) + 1);
				(void) strncpy(pname, devname,
				    (len - strlen(t)));

				if (meta_update_namespace(sp->setno, sideno,
				    ctd_name, mydev[i], key, pname,
				    ep) != 0) {
					goto out;
				}
			}
			rval = 0;
			break;
		} /* End of if (mydevs == mydev[i]) */
	} /* end of for loop */
out:
	if (pname != NULL)
		Free(pname);
	if (ctd_name != NULL)
		Free(ctd_name);
	if (devname != NULL)
		Free(devname);
	if (mydev != NULL)
		Free(mydev);
	return (rval);
}
