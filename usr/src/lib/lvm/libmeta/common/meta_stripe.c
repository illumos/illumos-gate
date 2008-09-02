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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * stripe operations
 */

#include <limits.h>
#include <stdlib.h>
#include <meta.h>
#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_convert.h>

#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

/*
 * replace stripe/concat
 */
int
meta_stripe_replace(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	mdname_t	*oldnp,
	mdname_t	*newnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	replace_params_t	params;
	md_dev64_t	old_dev, new_dev;
	diskaddr_t	new_start_blk;
	diskaddr_t	new_end_blk, label, size, start_blk;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	new_dev = newnp->dev;
	new_start_blk = newnp->start_blk;
	new_end_blk = newnp->end_blk;

	meta_invalidate_name(stripenp);

	/* the old device binding is now established */
	if ((old_dev = oldnp->dev) == NODEV64)
		return (mdsyserror(ep, ENODEV, oldnp->cname));

	if (((strcmp(oldnp->rname, newnp->rname) == 0) &&
	    (old_dev != new_dev))) {
		newnp->dev = new_dev;
		newnp->start_blk = new_start_blk;
		newnp->end_blk = new_end_blk;
	}

	if ((size = metagetsize(newnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((label = metagetlabel(newnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((start_blk = metagetstart(sp, newnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if (start_blk >= size) {
		(void) mdsyserror(ep, ENOSPC, newnp->cname);
		return (-1);
	}

	/* In dryrun mode (DOIT not set) we must not alter the mddb */
	if (options & MDCMD_DOIT) {
		if (add_key_name(sp, newnp, NULL, ep) != 0)
			return (-1);
	}

	/*
	 * There is no need to call meta_fixdevid() here as this function is
	 * only called by the metareplace -c command which actually does
	 * nothing (in terms of a resync) and thus does nothing with the devid.
	 */

	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(stripenp->dev);
	MD_SETDRIVERNAME(&params, MD_STRIPE, sp->setno);

	params.cmd = REPLACE_COMP;
	params.old_dev = old_dev;
	params.new_dev = new_dev;
	params.new_key = newnp->key;
	params.start_blk = newnp->start_blk;
	params.number_blks = size;
	/* Is this just a dryrun ? */
	if ((options & MDCMD_DOIT) == 0) {
		params.options |= MDIOCTL_DRYRUN;
	}
	if (label == 0)
		params.has_label = 0;
	else
		params.has_label = 1;
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0) {
		if (options & MDCMD_DOIT)
			(void) del_key_name(sp, newnp, ep);
		return (mdstealerror(ep, &params.mde));
	}
	meta_invalidate_name(oldnp);
	meta_invalidate_name(newnp);
	meta_invalidate_name(stripenp);

	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is replaced with %s\n"),
		    stripenp->cname, oldnp->cname, newnp->cname);

	}
	return (0);
}


/*
 * FUNCTION:	meta_get_stripe_names()
 * INPUT:	sp	- the set name to get stripes from
 *		options	- options from the command line
 * OUTPUT:	nlpp	- list of all stripe names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	returns a list of all stripes in the metadb
 *		for all devices in the specified set
 */
int
meta_get_stripe_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	return (meta_get_names(MD_STRIPE, sp, nlpp, options, ep));
}

/*
 * free stripe
 */
void
meta_free_stripe(
	md_stripe_t	*stripep
)
{
	uint_t		row;

	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];

		if (rp->comps.comps_val != NULL) {
			assert(rp->comps.comps_len > 0);
			Free(rp->comps.comps_val);
		}
	}
	if (stripep->rows.rows_val != NULL) {
		assert(stripep->rows.rows_len > 0);
		Free(stripep->rows.rows_val);
	}
	Free(stripep);
}


/*
 * get stripe (common)
 */
md_stripe_t *
meta_get_stripe_common(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	int		fast,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = stripenp->drivenamep;
	char		*miscname;
	ms_unit_t	*ms;
	md_stripe_t	*stripep;
	uint_t		row;

	/* must have set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	/* short circuit */
	if (dnp->unitp != NULL) {
		assert(dnp->unitp->type == MD_DEVICE);
		return ((md_stripe_t *)dnp->unitp);
	}

	/* get miscname and unit */
	if ((miscname = metagetmiscname(stripenp, ep)) == NULL)
		return (NULL);
	if (strcmp(miscname, MD_STRIPE) != 0) {
		(void) mdmderror(ep, MDE_NOT_STRIPE,
		    meta_getminor(stripenp->dev), stripenp->cname);
		return (NULL);
	}
	if ((ms = (ms_unit_t *)meta_get_mdunit(sp, stripenp, ep)) == NULL)
		return (NULL);
	assert(ms->c.un_type == MD_DEVICE);

	/* allocate stripe */
	stripep = Zalloc(sizeof (*stripep));

	/* allocate rows */
	assert(ms->un_nrows > 0);
	stripep->rows.rows_len = ms->un_nrows;
	stripep->rows.rows_val = Zalloc(stripep->rows.rows_len *
	    sizeof (*stripep->rows.rows_val));

	/* get common info */
	stripep->common.namep = stripenp;
	stripep->common.type = ms->c.un_type;
	stripep->common.state = ms->c.un_status;
	stripep->common.capabilities = ms->c.un_capabilities;
	stripep->common.parent = ms->c.un_parent;
	stripep->common.size = ms->c.un_total_blocks;
	stripep->common.user_flags = ms->c.un_user_flags;
	stripep->common.revision = ms->c.un_revision;

	/* get options */
	if ((ms->un_hsp_id != MD_HSP_NONE) &&
	    ((stripep->hspnamep = metahsphspname(&sp, ms->un_hsp_id,
	    ep)) == NULL)) {
		goto out;
	}

	/* get rows */
	for (row = 0; (row < ms->un_nrows); ++row) {
		struct ms_row	*mdr = &ms->un_row[row];
		struct ms_comp	*mdcomp = (void *)&((char *)ms)[ms->un_ocomp];
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp, c;

		/* get interlace */
		rp->interlace = mdr->un_interlace;

		/* allocate comps */
		assert(mdr->un_ncomp > 0);
		rp->comps.comps_len = mdr->un_ncomp;
		rp->comps.comps_val = Zalloc(rp->comps.comps_len *
		    sizeof (*rp->comps.comps_val));

		/* get components */
		for (comp = 0, c = mdr->un_icomp; (comp < mdr->un_ncomp);
		    ++comp, ++c) {
			struct ms_comp	*mdc = &mdcomp[c];
			diskaddr_t	comp_start_blk = mdc->un_start_block;
			md_comp_t	*cp = &rp->comps.comps_val[comp];

			/* get the component name */
			cp->compnamep = metakeyname(&sp, mdc->un_key, fast, ep);
			if (cp->compnamep == NULL)
				goto out;

			/* if hotspared */
			if (mdc->un_mirror.ms_hs_id != 0) {
				diskaddr_t hs_start_blk = mdc->un_start_block;

				/* get the hotspare name */
				cp->hsnamep = metakeyname(&sp,
				    mdc->un_mirror.ms_hs_key, fast, ep);
				if (cp->hsnamep == NULL)
					goto out;

				if (getenv("META_DEBUG_START_BLK") != NULL) {
					if (metagetstart(sp, cp->hsnamep,
					    ep) == MD_DISKADDR_ERROR)
						mdclrerror(ep);

					if ((cp->hsnamep->start_blk == 0) &&
					    (hs_start_blk != 0))
						md_eprintf(dgettext(TEXT_DOMAIN,
						    "%s: suspected bad"
						    "start block,"
						    " seems labelled"
						    "[stripe/hs]\n"),
						    cp->hsnamep->cname);

					if ((cp->hsnamep->start_blk > 0) &&
					    (hs_start_blk == 0) &&
					    ! ((row == 0) && (comp == 0)))
						md_eprintf(dgettext(TEXT_DOMAIN,
						    "%s: suspected bad"
						    "start block, "
						    "seems unlabelled"
						    "[stripe/hs]\n"),
						    cp->hsnamep->cname);
				}
				/* override any start_blk */
				cp->hsnamep->start_blk = hs_start_blk;

				/* get the right component start_blk */
				comp_start_blk = mdc->un_mirror.ms_orig_blk;
			} else {
				if (getenv("META_DEBUG_START_BLK") != NULL) {
					if (metagetstart(sp, cp->compnamep,
					    ep) == MD_DISKADDR_ERROR)
						mdclrerror(ep);

					if ((cp->compnamep->start_blk == 0) &&
					    (comp_start_blk != 0))
						md_eprintf(dgettext(TEXT_DOMAIN,
						    "%s: suspected bad"
						    "start block,"
						    " seems labelled"
						    "[stripe]"),
						    cp->compnamep->cname);

					if ((cp->compnamep->start_blk > 0) &&
					    (comp_start_blk == 0) &&
					    ! ((row == 0) && (comp == 0)))
						md_eprintf(dgettext(TEXT_DOMAIN,
						    "%s: suspected bad"
						    "start block, "
						    "seems unlabelled"
						    "[stripe]"),
						    cp->compnamep->cname);
				}
			}

			/* override any start_blk */
			cp->compnamep->start_blk = comp_start_blk;

			/* get state */
			cp->state = mdc->un_mirror.ms_state;

			/* get time of last state change */
			cp->timestamp = mdc->un_mirror.ms_timestamp;

			/* get lasterr count */
			cp->lasterrcnt = mdc->un_mirror.ms_lasterrcnt;
		}
	}

	/* cleanup, return success */
	Free(ms);
	dnp->unitp = (md_common_t *)stripep;
	return (stripep);

	/* cleanup, return error */
out:
	Free(ms);
	meta_free_stripe(stripep);
	return (NULL);
}

/*
 * get stripe
 */
md_stripe_t *
meta_get_stripe(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	md_error_t	*ep
)
{
	return (meta_get_stripe_common(sp, stripenp, 0, ep));
}

/*
 * check stripe for dev
 */
static int
in_stripe(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	uint_t		row;

	/* should be in the same set */
	assert(sp != NULL);

	/* get unit */
	if ((stripep = meta_get_stripe(sp, stripenp, ep)) == NULL)
		return (-1);

	/* look in rows */
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		/* look in columns */
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;
			diskaddr_t	comp_sblk;
			int		err;

			/* check same drive since metagetstart() can fail */
			if ((err = meta_check_samedrive(np, compnp, ep)) < 0)
				return (-1);
			else if (err == 0)
				continue;

			/* check overlap */
			if ((comp_sblk = metagetstart(sp, compnp, ep)) ==
			    MD_DISKADDR_ERROR)
				return (-1);
			if (meta_check_overlap(stripenp->cname, np,
			    slblk, nblks, compnp, comp_sblk, -1,
			    ep) != 0) {
				return (-1);
			}
		}
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a stripe
 */
int
meta_check_instripe(
	mdsetname_t	*sp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdnamelist_t	*stripenlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each stripe */
	if (meta_get_stripe_names(sp, &stripenlp, 0, ep) < 0)
		return (-1);
	for (p = stripenlp; (p != NULL); p = p->next) {
		mdname_t	*stripenp = p->namep;

		/* check stripe */
		if (in_stripe(sp, stripenp, np, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreenamelist(stripenlp);
	return (rval);
}

/*
 * check component
 */
int
meta_check_component(
	mdsetname_t	*sp,
	mdname_t	*np,
	int		force,
	md_error_t	*ep
)
{
	mdchkopts_t	options = (MDCHK_ALLOW_MDDB);
	md_common_t	*mdp;

	/*
	 * See if we are a soft partition: meta_sp_issp() returns 0 if
	 * np points to a soft partition, so the if and else clauses
	 * here represent "not a soft partition" and "soft partition,"
	 * respectively.
	 */
	if (meta_sp_issp(sp, np, ep) != 0) {
		/* make sure we have a disk */
		if (metachkcomp(np, ep) != 0)
			return (-1);
	} else {
		/* make sure soft partition can parent & doesn't have parent */
		if ((mdp = meta_get_unit(sp, np, ep)) == NULL)
			return (mdmderror(ep, MDE_INVAL_UNIT, NULL,
			    np->cname));
		if (mdp->capabilities == MD_CANT_PARENT)
			return (mdmderror(ep, MDE_INVAL_UNIT, NULL,
			    np->cname));
		if (MD_HAS_PARENT(mdp->parent)) {
			mdname_t *pnp;

			pnp = metamnumname(&sp, mdp->parent, 0, ep);
			if (pnp == NULL) {
				return (-1);
			}

			return (mduseerror(ep, MDE_ALREADY, np->dev,
			    pnp->cname, np->cname));
		}
	}

	/* check to ensure that it is not already in use */
	if ((! force) &&
	    (meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0)) {
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
 * print stripe
 */
static int
stripe_print(
	md_stripe_t	*stripep,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		row;
	int		rval = -1;

	if (options & PRINT_LARGEDEVICES) {
		if (stripep->common.revision != MD_64BIT_META_DEV) {
			rval = 0;
			goto out;
		}
	}

	if (options & PRINT_FN) {
		if (stripep->common.revision != MD_FN_META_DEV) {
			rval = 0;
			goto out;
		}
	}

	/* print name and num rows */
	if (fprintf(fp, "%s %u",
	    stripep->common.namep->cname, stripep->rows.rows_len) == EOF)
		goto out;

	/* print rows */
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		/* print num components */
		if (fprintf(fp, " %u", rp->comps.comps_len) == EOF)
			goto out;

		/*
		 * Print components. Always print the full path name.
		 */
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];

			if (fprintf(fp, " %s", cp->compnamep->rname) == EOF)
				goto out;
		}

		/* print interlace */
		if (rp->comps.comps_len > 1)
			if (fprintf(fp, " -i %lldb", rp->interlace) == EOF)
				goto out;

		/* print continuation */
		if (row != (stripep->rows.rows_len - 1))
			if (fprintf(fp, " \\\n\t") == EOF)
				goto out;
	}

	/* print hotspare name */
	if (stripep->hspnamep != NULL)
		if (fprintf(fp, " -h %s", stripep->hspnamep->hspname) == EOF)
			goto out;

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

/*
 * convert component state to name
 */
char *
comp_state_to_name(
	md_comp_t	*mdcp,
	md_timeval32_t	*tvp,
	uint_t		tstate	/* Errored tstate flags */
)
{
	comp_state_t	state = mdcp->state;

	/* grab time */
	if (tvp != NULL)
		*tvp = mdcp->timestamp;

	if (tstate != 0) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* return state */
	switch (state) {
	case CS_OKAY:
		return (dgettext(TEXT_DOMAIN, "Okay"));
	case CS_ERRED:
		return (dgettext(TEXT_DOMAIN, "Maintenance"));
	case CS_LAST_ERRED:
		return (dgettext(TEXT_DOMAIN, "Last Erred"));
	case CS_RESYNC:
		return (dgettext(TEXT_DOMAIN, "Resyncing"));
	default:
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

/*
 * print subdevice stripe row
 */
static int
subdev_row_report(
	mdsetname_t	*sp,
	md_row_t	*rp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	uint_t		top_tstate,	/* Errored tstate flags */
	md_error_t	*ep
)
{
	uint_t		comp;
	int		rval = -1;
	ddi_devid_t	dtp;
	int		len = 0;


	/*
	 * building a format string on the fly that will be used
	 * in fprintf. This is to allow really really long ctd names
	 */
	for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
		md_comp_t	*cp = &rp->comps.comps_val[comp];
		char		*cname = cp->compnamep->cname;

		len = max(len, strlen(cname));
	}

	len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
	len += 2;
	/* print header */
	if (! (options & PRINT_TIMES)) {
		if (fprintf(fp,
		    "\t%-*.*s %-12.12s %5.5s %12.12s %5.5s %s\n",
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
		    "\t%-*s %5s %5s %-11s %-5s %-9s %s\n",
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


	/* print components */
	for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
		md_comp_t	*cp = &rp->comps.comps_val[comp];
		mdname_t	*namep = cp->compnamep;
		char		*cname = namep->cname;
		diskaddr_t	start_blk;
		int		has_mddb;
		char		*has_mddb_str;
		char		*comp_state;
		md_timeval32_t	tv;
		char		*hsname = ((cp->hsnamep != NULL) ?
		    cp->hsnamep->cname : "");
		char		*devid = " ";
		mdname_t	*didnp = NULL;
		uint_t		tstate = 0;

		/* get info */
		if ((start_blk = metagetstart(sp, namep, ep)) ==
		    MD_DISKADDR_ERROR) {
			return (-1);
		}
		if ((has_mddb = metahasmddb(sp, namep, ep)) < 0) {
			return (-1);
		}
		if (has_mddb)
			has_mddb_str = dgettext(TEXT_DOMAIN, "Yes");
		else
			has_mddb_str = dgettext(TEXT_DOMAIN, "No");

		/*
		 * If the component is a metadevice, print out either
		 * unavailable or the state of the metadevice, if not
		 * a metadevice, print nothing if the state of the
		 * stripe is unavailable
		 */
		if (metaismeta(namep)) {
			if (meta_get_tstate(namep->dev, &tstate, ep) != 0)
				return (-1);
			comp_state = comp_state_to_name(cp, &tv, tstate &
			    MD_DEV_ERRORED);
		} else {
			/*
			 * if top_tstate is set, that implies that you have
			 * a ctd type device with an unavailable metadevice
			 * on top of it. If so, print a - for it's state
			 */
			if (top_tstate != 0)
				comp_state = "-";
			else
				comp_state = comp_state_to_name(cp, &tv,
				    tstate & MD_DEV_ERRORED);
		}

		/* populate the key in the name_p structure */
		if ((didnp = metadevname(&sp, namep->dev, ep))
		    == NULL) {
			return (-1);
		}

	    /* determine if devid does NOT exist */
		if (options & PRINT_DEVID) {
			if ((dtp = meta_getdidbykey(sp->setno,
			    getmyside(sp, ep), didnp->key, ep)) == NULL)
				devid = dgettext(TEXT_DOMAIN, "No ");
			else {
				devid = dgettext(TEXT_DOMAIN, "Yes");
				free(dtp);
			}
		}
		/* print info */
		/*
		 * building a format string on the fly that will be used
		 * in fprintf. This is to allow really really long ctd names
		 */
		if (! (options & PRINT_TIMES)) {
			if (fprintf(fp,
			    "\t%-*s %8lld     %-5.5s %12.12s %5.5s %s\n",
			    len, cname, start_blk,
			    has_mddb_str, comp_state, devid, hsname) == EOF) {
				goto out;
			}
		} else {
			char	*timep = meta_print_time(&tv);

			if (fprintf(fp,
			    "\t%-*s %5lld %-5s %-11s %-5s %-9s %s\n",
			    len, cname, start_blk,
			    has_mddb_str, comp_state, devid, hsname,
			    timep) == EOF) {
				goto out;
			}
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
 * print toplevel stripe row
 */
/*ARGSUSED4*/
static int
toplev_row_report(
	mdsetname_t	*sp,
	md_row_t	*rp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		comp;
	int		rval = -1;
	char		*devid = " ";
	mdname_t	*didnp = NULL;
	int		len = 0;

	/*
	 * building a format string on the fly that will be used
	 * in fprintf. This is to allow really really long ctd names
	 */
	for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
		len = max(len,
		    strlen(rp->comps.comps_val[comp].compnamep->cname));
	}

	len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
	len += 2;
	/* print header */
	if (fprintf(fp,
	    "\t%-*.*s %-12.12s %-5.5s\t%s\n",
	    len, len,
	    dgettext(TEXT_DOMAIN, "Device"),
	    dgettext(TEXT_DOMAIN, "Start Block"),
	    dgettext(TEXT_DOMAIN, "Dbase"),
	    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
		goto out;
	}

	/* print components */
	for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
		md_comp_t	*cp = &rp->comps.comps_val[comp];
		mdname_t	*namep = cp->compnamep;
		char		*cname = namep->cname;
		diskaddr_t	start_blk;
		int		has_mddb;
		char		*has_mddb_str;
		ddi_devid_t	dtp;

		/* get info */
		if ((start_blk = metagetstart(sp, namep, ep)) ==
		    MD_DISKADDR_ERROR) {
			return (-1);
		}
		if ((has_mddb = metahasmddb(sp, namep, ep)) < 0) {
			return (-1);
		}
		if (has_mddb)
			has_mddb_str = dgettext(TEXT_DOMAIN, "Yes");
		else
			has_mddb_str = dgettext(TEXT_DOMAIN, "No");

		/* populate the key in the name_p structure */
		if ((didnp = metadevname(&sp, namep->dev, ep))
		    == NULL) {
			return (-1);
		}

		/* determine if devid does NOT exist */
		if (options & PRINT_DEVID) {
			if ((dtp = meta_getdidbykey(sp->setno,
			    getmyside(sp, ep), didnp->key, ep)) == NULL) {
				devid = dgettext(TEXT_DOMAIN, "No ");
			} else {
				devid = dgettext(TEXT_DOMAIN, "Yes");
				free(dtp);
			}
		}
		/* print info */
		/*
		 * building a format string on the fly that will be used
		 * in fprintf. This is to allow really really long ctd names
		 */
		if (fprintf(fp,
		    "\t%-*s %8lld     %-5.5s\t%s\n", len,
		    cname, start_blk, has_mddb_str, devid) == EOF) {
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
 * print stripe options
 */
int
meta_print_stripe_options(
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
 * report stripe
 */
static int
stripe_report(
	mdsetname_t	*sp,
	md_stripe_t	*stripep,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		row;
	int		rval = -1;
	uint_t		tstate = 0;

	/*
	 * if the -B option has been specified check to see if the
	 * metadevice is s "big" one and print if so, also if a
	 * big device we need to store the ctd involved for use in
	 * printing out the relocation information.
	 */
	if (options & PRINT_LARGEDEVICES) {
		if ((stripep->common.revision & MD_64BIT_META_DEV) == 0) {
			rval = 0;
			goto out;
		} else {
			if (meta_getdevs(sp, stripep->common.namep,
			    nlpp, ep) != 0)
				goto out;
		}
	}

	/*
	 * if the -D option has been specified check to see if the
	 * metadevice has a descriptive name and print if so, also if a
	 * descriptive device name we need to store the ctd involved
	 * for use in printing out the relocation information.
	 */
	if (options & PRINT_FN) {
		if ((stripep->common.revision & MD_FN_META_DEV) == 0) {
			rval = 0;
			goto out;
		} else {
			if (meta_getdevs(sp, stripep->common.namep,
			    nlpp, ep) != 0)
				goto out;
		}
	}

	/* print header */
	if (options & PRINT_HEADER) {
		if (fprintf(fp, "%s: Concat/Stripe\n",
		    stripep->common.namep->cname) == EOF) {
			goto out;
		}

	}

	/* print hotspare pool */
	if (stripep->hspnamep != NULL) {
		if (meta_print_stripe_options(stripep->hspnamep,
		    fname, fp, ep) != 0) {
			return (-1);
		}
	}

	if (metaismeta(stripep->common.namep)) {
		if (meta_get_tstate(stripep->common.namep->dev, &tstate, ep)
		    != 0)
			return (-1);
	}
	if ((tstate & MD_DEV_ERRORED) != 0) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    State: Unavailable\n"
		    "    Reconnect disk and invoke: metastat -i\n")) == EOF) {
			goto out;
		}
	}

	/* print size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %lld blocks (%s)\n"),
	    stripep->common.size,
	    meta_number_to_string(stripep->common.size, DEV_BSIZE))
	    == EOF) {
		goto out;
	}

	/* print rows */
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];

		/* print stripe and interlace */
		if (rp->comps.comps_len > 1) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Stripe %u: (interlace: %lld blocks)\n"),
			    row, rp->interlace) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Stripe %u:\n"),
			    row) == EOF) {
				goto out;
			}
		}

		/* print components appropriately */
		if (MD_HAS_PARENT(stripep->common.parent)) {
			if (subdev_row_report(sp, rp, fname, fp, options,
			    tstate & MD_DEV_ERRORED, ep) != 0) {
				return (-1);
			}
		} else {
			if (toplev_row_report(sp, rp, fname, fp, options,
			    ep) != 0) {
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
 * print/report stripe
 */
int
meta_stripe_print(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	int		row, comp;

	/* should have same set */
	assert(sp != NULL);
	assert((stripenp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev))));

	/* print all stripes */
	if (stripenp == NULL) {
		mdnamelist_t	*nlp = NULL;
		mdnamelist_t	*p;
		int		cnt;
		int		rval = 0;

		/* get list */
		if ((cnt = meta_get_stripe_names(sp, &nlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recurse */
		for (p = nlp; (p != NULL); p = p->next) {
			mdname_t	*np = p->namep;

			if (meta_stripe_print(sp, np, nlpp, fname, fp,
			    options, ep) != 0)
				rval = -1;
		}

		/* cleanup, return success */
		metafreenamelist(nlp);
		return (rval);
	}

	/* get unit structure */
	if ((stripep = meta_get_stripe_common(sp, stripenp,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* check for parented */
	if ((! (options & PRINT_SUBDEVS)) &&
	    (MD_HAS_PARENT(stripep->common.parent))) {
		return (0);
	}

	/* print appropriate detail */
	if (options & PRINT_SHORT) {
		if (stripe_print(stripep, fname, fp, options, ep) != 0)
			return (-1);
	} else {
		if (stripe_report(sp, stripep, nlpp, fname, fp, options,
		    ep) != 0)
			return (-1);
	}

	/* Recurse on components that are metadevices */
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];

		/* look for components that are metadevices */
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*namep = cp->compnamep;

			if ((metaismeta(namep)) &&
			    (meta_print_name(sp, namep, nlpp, fname, fp,
			    (options | PRINT_HEADER | PRINT_SUBDEVS),
			    NULL, ep) != 0)) {
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * find stripe component to replace
 */
int
meta_find_erred_comp(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	mdname_t	**compnpp,
	comp_state_t	*compstate,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	md_comp_t	*compp = NULL;
	uint_t		lasterrcnt = 0;
	uint_t		row;

	/* get stripe */
	*compnpp = NULL;
	if ((stripep = meta_get_stripe_common(sp, stripenp, 1, ep)) == NULL)
		return (-1);

	/*
	 * Try to find the first erred component.
	 * If there is not one, then look for the
	 *	first last_erred component.
	 */
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];

			if ((cp->state == CS_ERRED) && ((compp == NULL) ||
			    (cp->lasterrcnt < lasterrcnt))) {
				compp = cp;
				lasterrcnt = cp->lasterrcnt;
			}
		}
	}
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];

			if ((cp->state == CS_LAST_ERRED) && ((compp == NULL) ||
			    (cp->lasterrcnt < lasterrcnt))) {
				compp = cp;
				lasterrcnt = cp->lasterrcnt;
			}
		}
	}

	/* return component */
	if (compp != NULL) {
		*compnpp = compp->compnamep;
		*compstate = compp->state;
	}

	/* return success */
	return (0);
}

/*
 * invalidate component names
 */
static int
invalidate_components(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	uint_t		row;

	if ((stripep = meta_get_stripe(sp, stripenp, ep)) == NULL)
		return (-1);
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;

			meta_invalidate_name(compnp);
		}
	}
	return (0);
}

/*
 * attach components to stripe
 */
int
meta_stripe_attach(
	mdsetname_t		*sp,
	mdname_t		*stripenp,
	mdnamelist_t		*nlp,
	diskaddr_t		interlace,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	mdnamelist_t		*lp;
	ms_unit_t		*old_un, *new_un;
	struct ms_row		*mdr, *new_mdr;
	uint_t			newcomps, ncomps, icomp;
	uint_t			row;
	size_t			mdsize, first_comp;
	diskaddr_t		new_blks;
	diskaddr_t		limit;
	diskaddr_t		disk_size = 0;
	ms_comp_t		*mdcomp, *new_comp;
	uint_t			write_reinstruct = 0;
	uint_t			read_reinstruct = 0;
	mdnamelist_t		*keynlp = NULL;
	uint_t			round_cyl = 1;
	minor_t			parent;
	md_grow_params_t	mgp;
	int			rval = -1;
	md_timeval32_t		creation_time;
	int			create_flag = MD_CRO_32BIT;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	/* check type */
	if (metachkmeta(stripenp, ep) != 0)
		return (-1);

	/* check and count components */
	assert(nlp != NULL);
	newcomps = 0;
	for (lp = nlp; (lp != NULL); lp = lp->next) {
		mdname_t	*np = lp->namep;
		mdnamelist_t	*p;

		/* check against existing devices */
		if (meta_check_component(sp, np, 0, ep) != 0)
			return (-1);

		/* check against ourselves */
		for (p = lp->next; (p != NULL); p = p->next) {
			if (meta_check_overlap(np->cname, np, 0, -1,
			    p->namep, 0, -1, ep) != 0) {
				return (-1);
			}
		}

		/* count */
		++newcomps;
	}

	/* get old unit */
	if ((old_un = (ms_unit_t *)meta_get_mdunit(sp, stripenp, ep)) == NULL)
		return (-1);

	/* if zero, inherit the last rows interlace value */
	if (interlace == 0) {
		mdr = &old_un->un_row[old_un->un_nrows - 1];
		interlace = mdr->un_interlace;
	}

	/*
	 * calculate size of new unit structure
	 */

	/* unit + rows */
	mdsize = sizeof (ms_unit_t) - sizeof (struct ms_row);
	mdsize += sizeof (struct ms_row) * (old_un->un_nrows + 1);

	/* number of new components being added */
	ncomps = newcomps;

	/* count the # of components in the old unit */
	mdr = &old_un->un_row[0];
	for (row = 0; (row < old_un->un_nrows); row++)
		ncomps += mdr[row].un_ncomp;
	first_comp = roundup(mdsize, sizeof (long long));
	mdsize += sizeof (ms_comp_t) * ncomps + (first_comp - mdsize);

	/* allocate new unit */
	new_un = Zalloc(mdsize);
	new_un->un_ocomp = first_comp;

	/* compute new data */
	new_mdr = &new_un->un_row[old_un->un_nrows];
	new_mdr->un_icomp = ncomps - newcomps;
	new_mdr->un_ncomp = newcomps;
	new_mdr->un_blocks = 0;
	new_mdr->un_cum_blocks =
	    old_un->un_row[old_un->un_nrows - 1].un_cum_blocks;
	new_mdr->un_interlace = interlace;

	/* for each new device */
	mdcomp = (struct ms_comp *)(void *)&((char *)new_un)[new_un->un_ocomp];
	icomp = new_mdr->un_icomp;
	if (meta_gettimeofday(&creation_time) == -1)
		return (mdsyserror(ep, errno, NULL));
	for (lp = nlp; (lp != NULL); lp = lp->next) {
		mdname_t	*np = lp->namep;
		diskaddr_t	size, start_blk;
		mdgeom_t		*geomp;

		/* figure out how big */
		if ((size = metagetsize(np, ep)) == MD_DISKADDR_ERROR)
			goto out;
		if ((start_blk = metagetstart(sp, np, ep)) ==
		    MD_DISKADDR_ERROR)
			goto out;
		if (start_blk >= size) {
			(void) mdsyserror(ep, ENOSPC, np->cname);
			goto out;
		}
		size -= start_blk;
		if (newcomps > 1)
			size = rounddown(size, interlace);

		/* adjust for smallest disk */
		if (disk_size == 0) {
			disk_size = size;
		} else if (size < disk_size) {
			disk_size = size;
		}

		/* get worst reinstructs */
		if ((geomp = metagetgeom(np, ep)) == NULL)
			goto out;
		if (geomp->write_reinstruct > write_reinstruct)
			write_reinstruct = geomp->write_reinstruct;
		if (geomp->read_reinstruct > read_reinstruct)
			read_reinstruct = geomp->read_reinstruct;

		/* In dryrun mode (DOIT not set) we must not alter the mddb */
		if (options & MDCMD_DOIT) {
			/* store name in namespace */
			if (add_key_name(sp, np, &keynlp, ep) != 0)
				goto out;
		}

		/* build new component */
		new_comp = &mdcomp[icomp++];
		new_comp->un_key = np->key;
		new_comp->un_dev = np->dev;
		new_comp->un_start_block = start_blk;
		new_comp->un_mirror.ms_state = CS_OKAY;
		new_comp->un_mirror.ms_timestamp = creation_time;
	}

	limit = LLONG_MAX;

	/* compute new size */
	new_mdr->un_blocks = new_mdr->un_ncomp * disk_size;
	new_blks = new_mdr->un_cum_blocks + new_mdr->un_blocks;
	if (new_blks > limit) {
		new_mdr->un_cum_blocks = limit;
		new_blks = limit;
		md_eprintf(dgettext(TEXT_DOMAIN,
		    "unit size overflow, limit is %lld blocks\n"),
		    limit);
	} else {
		new_mdr->un_cum_blocks += new_mdr->un_blocks;
	}
	new_un->c.un_actual_tb = new_mdr->un_cum_blocks;
	new_un->un_nrows = old_un->un_nrows + 1;

	/* adjust geometry */
	new_un->c.un_nhead = old_un->c.un_nhead;
	new_un->c.un_nsect = old_un->c.un_nsect;
	new_un->c.un_rpm = old_un->c.un_rpm;
	new_un->c.un_wr_reinstruct = old_un->c.un_wr_reinstruct;
	new_un->c.un_rd_reinstruct = old_un->c.un_rd_reinstruct;
	if (meta_adjust_geom((md_unit_t *)new_un, stripenp,
	    write_reinstruct, read_reinstruct, round_cyl, ep) != 0)
		goto out;

	/* if in dryrun mode, we are done here. */
	if ((options & MDCMD_DOIT) == 0)  {
		if (options & MDCMD_PRINT) {
			if (newcomps == 1) {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "%s: attaching component would suceed\n"),
				    stripenp->cname);
			} else {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "%s: attaching components would suceed\n"),
				    stripenp->cname);
			}
		}
		rval = 0; /* success */
		goto out;
	}

	create_flag = meta_check_devicesize(new_un->c.un_total_blocks);

	/* grow stripe */
	(void) memset(&mgp, 0, sizeof (mgp));
	mgp.mnum = MD_SID(old_un);
	MD_SETDRIVERNAME(&mgp, MD_STRIPE, sp->setno);
	mgp.size = mdsize;
	mgp.mdp = (uintptr_t)new_un;
	mgp.nrows = old_un->un_nrows;
	if (create_flag == MD_CRO_32BIT) {
		mgp.options = MD_CRO_32BIT;
		new_un->c.un_revision &= ~MD_64BIT_META_DEV;
	} else {
		mgp.options = MD_CRO_64BIT;
		new_un->c.un_revision |= MD_64BIT_META_DEV;
	}

	if ((MD_HAS_PARENT(old_un->c.un_parent)) &&
	    (old_un->c.un_parent != MD_MULTI_PARENT)) {
		mgp.npar = 1;
		parent = old_un->c.un_parent;
		mgp.par = (uintptr_t)(&parent);
	}

	if (metaioctl(MD_IOCGROW, &mgp, &mgp.mde, NULL) != 0) {
		(void) mdstealerror(ep, &mgp.mde);
		goto out;
	}

	/* clear cache */
	if (invalidate_components(sp, stripenp, ep) != 0)
		goto out;
	meta_invalidate_name(stripenp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		if (newcomps == 1) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: component is attached\n"), stripenp->cname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: components are attached\n"), stripenp->cname);
		}
		(void) fflush(stdout);
	}

	/* grow any parents */
	if (meta_concat_parent(sp, stripenp, ep) != 0)
		return (-1);

	rval = 0;	/* success */

	/* cleanup, return error */
out:
	Free(old_un);
	Free(new_un);
	if (options & MDCMD_DOIT) {
		if (rval != 0)
			(void) del_key_names(sp, keynlp, NULL);
		metafreenamelist(keynlp);
	}
	return (rval);
}

/*
 * get stripe parameters
 */
int
meta_stripe_get_params(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	ms_params_t	*paramsp,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	/* check name */
	if (metachkmeta(stripenp, ep) != 0)
		return (-1);

	/* get unit */
	if ((stripep = meta_get_stripe(sp, stripenp, ep)) == NULL)
		return (-1);

	/* return parameters */
	(void) memset(paramsp, 0, sizeof (*paramsp));
	if (stripep->hspnamep == NULL)
		paramsp->hsp_id = MD_HSP_NONE;
	else
		paramsp->hsp_id = stripep->hspnamep->hsp;
	return (0);
}

/*
 * set stripe parameters
 */
int
meta_stripe_set_params(
	mdsetname_t		*sp,
	mdname_t		*stripenp,
	ms_params_t		*paramsp,
	md_error_t		*ep
)
{
	md_stripe_params_t	msp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev)));

	/* check name */
	if (metachkmeta(stripenp, ep) != 0)
		return (-1);

	/* set parameters */
	(void) memset(&msp, 0, sizeof (msp));
	MD_SETDRIVERNAME(&msp, MD_STRIPE, sp->setno);
	msp.mnum = meta_getminor(stripenp->dev);
	msp.params = *paramsp;
	if (metaioctl(MD_IOCCHANGE, &msp, &msp.mde, stripenp->cname) != 0)
		return (mdstealerror(ep, &msp.mde));

	/* clear cache */
	meta_invalidate_name(stripenp);

	/* return success */
	return (0);
}

/*
 * check for dups in the stripe itself
 */
static int
check_twice(
	md_stripe_t	*stripep,
	uint_t		row,
	uint_t		comp,
	md_error_t	*ep
)
{
	mdname_t	*stripenp = stripep->common.namep;
	mdname_t	*thisnp;
	uint_t		r;

	thisnp = stripep->rows.rows_val[row].comps.comps_val[comp].compnamep;
	for (r = 0; (r <= row); ++r) {
		md_row_t	*rp = &stripep->rows.rows_val[r];
		uint_t		e = ((r == row) ? comp : rp->comps.comps_len);
		uint_t		c;

		for (c = 0; (c < e); ++c) {
			md_comp_t	*cp = &rp->comps.comps_val[c];
			mdname_t	*compnp = cp->compnamep;

			if (meta_check_overlap(stripenp->cname, thisnp, 0, -1,
			    compnp, 0, -1, ep) != 0) {
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * default stripe interlace
 */
diskaddr_t
meta_default_stripe_interlace(void)
{
	diskaddr_t		interlace;

	/* default to 512k, round up if necessary */
	interlace = btodb(512 * 1024);
	if (interlace < btodb(MININTERLACE))
		interlace = roundup(MININTERLACE, interlace);
	return (interlace);
}

/*
 * convert interlaces
 */
int
meta_stripe_check_interlace(
	diskaddr_t	interlace,
	char		*uname,
	md_error_t	*ep
)
{
	if ((interlace < btodb(MININTERLACE)) ||
	    (interlace > btodb(MAXINTERLACE))) {
		return (mderror(ep, MDE_BAD_INTERLACE, uname));
	}
	return (0);
}


/*
 * check stripe
 */
int
meta_check_stripe(
	mdsetname_t	*sp,
	md_stripe_t	*stripep,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*stripenp = stripep->common.namep;
	int		force = ((options & MDCMD_FORCE) ? 1 : 0);
	int		doit = ((options & MDCMD_DOIT) ? 1 : 0);
	int		updateit = ((options & MDCMD_UPDATE) ? 1 : 0);
	uint_t		row;

	/* check rows */
	if (stripep->rows.rows_len < 1) {
		return (mdmderror(ep, MDE_BAD_STRIPE,
		    meta_getminor(stripenp->dev), stripenp->cname));
	}
	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		comp;

		/* check number */
		if (rp->comps.comps_len < 1) {
			return (mdmderror(ep, MDE_BAD_STRIPE,
			    meta_getminor(stripenp->dev), stripenp->cname));
		}

		/* compute default interlace */
		if (rp->interlace == 0) {
			rp->interlace = meta_default_stripe_interlace();
		}

		/* check interlace */
		if (meta_stripe_check_interlace(rp->interlace, stripenp->cname,
		    ep) != 0) {
			return (-1);
		}

		/* check components */
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;
			diskaddr_t	start_blk, size;

			/* check component */
			if (!updateit) {
				if (meta_check_component(sp, compnp,
				    force, ep) != 0)
					return (-1);
				if (((start_blk = metagetstart(sp, compnp,
				    ep)) == MD_DISKADDR_ERROR) ||
				    ((size = metagetsize(compnp, ep)) ==
				    MD_DISKADDR_ERROR)) {
					return (-1);
				}
				if (start_blk >= size)
					return (mdsyserror(ep, ENOSPC,
					    compnp->cname));
				size -= start_blk;
				size = rounddown(size, rp->interlace);
				if (size == 0)
					return (mdsyserror(ep, ENOSPC,
					    compnp->cname));
			}

			/* check this stripe too */
			if (check_twice(stripep, row, comp, ep) != 0)
				return (-1);
		}
	}

	/* check hotspare pool name */
	if (doit) {
		if ((stripep->hspnamep != NULL) &&
		    (metachkhsp(sp, stripep->hspnamep, ep) != 0)) {
			return (-1);
		}
	}

	/* return success */
	return (0);
}

/*
 * setup stripe geometry
 */
static int
stripe_geom(
	md_stripe_t	*stripep,
	ms_unit_t	*ms,
	md_error_t	*ep
)
{
	uint_t		nrow = stripep->rows.rows_len;
	uint_t		write_reinstruct = 0;
	uint_t		read_reinstruct = 0;
	uint_t		round_cyl = 1;
	uint_t		row;
	mdgeom_t	*geomp;
	diskaddr_t	first_row_size = 0;
	char		*miscname;
	int		is_sp = 0;

	/* get worst reinstructs */
	for (row = 0; (row < nrow); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		ncomp = rp->comps.comps_len;
		uint_t		comp;

		for (comp = 0; (comp < ncomp); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;

			if ((geomp = metagetgeom(compnp, ep)) == NULL)
				return (-1);
			if (geomp->write_reinstruct > write_reinstruct)
				write_reinstruct = geomp->write_reinstruct;
			if (geomp->read_reinstruct > read_reinstruct)
				read_reinstruct = geomp->read_reinstruct;
		}
	}

	if ((geomp = metagetgeom(
	    stripep->rows.rows_val[0].comps.comps_val[0].compnamep,
	    ep)) == NULL) {
		return (-1);
	}
	/*
	 * Figure out if the first component is a softpartition as the
	 * truncation check only occurs on them.
	 */
	if ((miscname = metagetmiscname(
	    stripep->rows.rows_val[0].comps.comps_val[0].compnamep,
	    ep)) == NULL) {
		if (!mdisdeverror(ep, MDE_NOT_META))
			return (-1);
	} else if (strcmp(miscname, MD_SP) == 0) {
		is_sp = 1;
	}

	/*
	 * If the stripe is to be multi-terabyte we should
	 * use EFI geometries, else we can get rounding errors
	 * in meta_setup_geom().
	 */

	if (ms->c.un_actual_tb > MD_MAX_BLKS_FOR_SMALL_DEVS) {
		geomp->nhead = MD_EFI_FG_HEADS;
		geomp->nsect = MD_EFI_FG_SECTORS;
		geomp->rpm = MD_EFI_FG_RPM;
	}

	/* setup geometry from first device */
	if (meta_setup_geom((md_unit_t *)ms, stripep->common.namep, geomp,
	    write_reinstruct, read_reinstruct, round_cyl, ep) != 0)
		return (-1);

	/*
	 * Here we want to make sure that any truncation did not
	 * result in lost data (or, more appropriately, inaccessible
	 * data).
	 *
	 * This is mainly a danger for (1, 1) concats, but it is
	 * mathematically possible for other somewhat contrived
	 * arrangements where in the sum of the lengths of each row
	 * beyond the first is smaller than the cylinder size of the
	 * only component in the first row.
	 *
	 * It is tempting to simply test for truncation here, by
	 * (md->c.un_total_blocks < md->c.un_actual_tb). That does
	 * not tell us, however, if rounding resulted in data loss,
	 * rather only that it occurred. The somewhat less obvious
	 * test below covers both the obvious (1, 1) case and the
	 * aforementioned corner case.
	 */
	first_row_size = ms->un_row[0].un_blocks;
	if (is_sp == 1) {
		md_unit_t	*md = (md_unit_t *)ms;

		if (md->c.un_total_blocks < first_row_size) {
			char buf[] = VAL2STR(ULLONG_MAX);

			/*
			 * The only difference here is the text of the error
			 * message, since the remediation is slightly
			 * different in the one-component versus
			 * multiple-component cases.
			 */
			if (nrow == 1) {
				(void) mderror(ep, MDE_STRIPE_TRUNC_SINGLE,
				    stripep->common.namep->cname);
			} else {
				(void) mderror(ep, MDE_STRIPE_TRUNC_MULTIPLE,
				    stripep->common.namep->cname);
			}

			/*
			 * By the size comparison above and the initialization
			 * of buf[] in terms of ULLONG_MAX, we guarantee that
			 * the value arg is non-negative and that we won't
			 * overflow the container.
			 */
			mderrorextra(ep, ulltostr((md->c.un_total_blocks +
			    (geomp->nhead * geomp->nsect))
			    - first_row_size, &buf[sizeof (buf) - 1]));

			return (-1);
		}
	}

	/* return success */
	return (0);
}

/*
 * create stripe
 */
int
meta_create_stripe(
	mdsetname_t	*sp,
	md_stripe_t	*stripep,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*stripenp = stripep->common.namep;
	int		force = ((options & MDCMD_FORCE) ? 1 : 0);
	int		doall = ((options & MDCMD_ALLOPTION) ? 1 : 0);
	uint_t		nrow = stripep->rows.rows_len;
	uint_t		ncomp = 0;
	uint_t		icomp = 0;
	diskaddr_t	cum_blocks = 0;
	diskaddr_t	limit;
	size_t		mdsize, first_comp;
	uint_t		row;
	ms_unit_t	*ms;
	ms_comp_t	*mdcomp;
	mdnamelist_t	*keynlp = NULL;
	md_set_params_t	set_params;
	int		rval = -1;
	md_timeval32_t	creation_time;
	int		create_flag = MD_CRO_32BIT;

	/* validate stripe */
	if (meta_check_stripe(sp, stripep, options, ep) != 0)
		return (-1);

	/* allocate stripe unit */
	mdsize = sizeof (*ms) - sizeof (ms->un_row[0]);
	mdsize += sizeof (ms->un_row) * nrow;
	for (row = 0; (row < nrow); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];

		ncomp += rp->comps.comps_len;
	}
	first_comp = roundup(mdsize, sizeof (long long));
	mdsize += (first_comp - mdsize) + (ncomp * sizeof (ms_comp_t));
	ms = Zalloc(mdsize);
	ms->un_ocomp = first_comp;
	if (meta_gettimeofday(&creation_time) == -1)
		return (mdsyserror(ep, errno, NULL));

	/* do rows */
	mdcomp = (ms_comp_t *)(void *)&((char *)ms)[ms->un_ocomp];
	for (row = 0; (row < nrow); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		uint_t		ncomp = rp->comps.comps_len;
		struct ms_row	*mdr = &ms->un_row[row];
		diskaddr_t	disk_size = 0;
		uint_t		comp;

		/* setup component count and offfset */
		mdr->un_icomp = icomp;
		mdr->un_ncomp = ncomp;

		/* do components */
		for (comp = 0; (comp < ncomp); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;
			ms_comp_t	*mdc = &mdcomp[icomp++];
			diskaddr_t	size, start_blk;

			/*
			 * get start and size
			 * if first component is labelled, include label
			 */
			if ((size = metagetsize(compnp, ep)) ==
			    MD_DISKADDR_ERROR)
				goto out;
			if ((start_blk = metagetstart(sp, compnp, ep)) ==
			    MD_DISKADDR_ERROR)
				goto out;
			if ((row == 0) && (comp == 0)) {
				diskaddr_t	label;
				int		has_db;

				if ((has_db = metahasmddb(sp, compnp, ep)) < 0)
					goto out;
				if ((label = metagetlabel(compnp, ep)) ==
				    MD_DISKADDR_ERROR)
					goto out;
				if ((has_db == 0) && (label != 0)) {
					ms->c.un_flag |= MD_LABELED;
					start_blk = compnp->start_blk = 0;
				}
			}
			/* make sure we still have something left */
			if (start_blk >= size) {
				(void) mdsyserror(ep, ENOSPC, compnp->cname);
				goto out;
			}
			size -= start_blk;

			/*
			 * round down by interlace: this only applies
			 * if this row is a stripe, as indicated by
			 * (ncomp > 1)
			 */
			if (ncomp > 1)
				size = rounddown(size, rp->interlace);

			if (size == 0) {
				(void) mdsyserror(ep, ENOSPC, compnp->cname);
				goto out;
			}

			/*
			 * adjust for smallest disk: for a concat (any
			 * row with only one component), this will
			 * never hit the second conditional.
			 */
			if (disk_size == 0) {
				disk_size = size;
			} else if (size < disk_size) {
				disk_size = size;
			}

			if (options & MDCMD_DOIT) {
				/* store name in namespace */
				if (add_key_name(sp, compnp, &keynlp, ep) != 0)
					goto out;
			}

			/* setup component */
			mdc->un_key = compnp->key;
			mdc->un_dev = compnp->dev;
			mdc->un_start_block = start_blk;
			mdc->un_mirror.ms_state = CS_OKAY;
			mdc->un_mirror.ms_timestamp = creation_time;
		}
		limit = LLONG_MAX;

		/* setup row */
		mdr->un_blocks = mdr->un_ncomp * disk_size;
		cum_blocks += mdr->un_blocks;
		if (cum_blocks > limit) {
			cum_blocks = limit;
			md_eprintf(dgettext(TEXT_DOMAIN,
			    "unit size overflow, limit is %lld blocks\n"),
			    limit);
		}
		mdr->un_cum_blocks = cum_blocks;
		mdr->un_interlace = rp->interlace;
	}

	/* setup unit */
	ms->c.un_type = MD_DEVICE;
	MD_SID(ms) = meta_getminor(stripenp->dev);
	ms->c.un_actual_tb = cum_blocks;
	ms->c.un_size = mdsize;
	if (stripep->hspnamep != NULL)
		ms->un_hsp_id = stripep->hspnamep->hsp;
	else
		ms->un_hsp_id = MD_HSP_NONE;
	ms->un_nrows = nrow;

	/* fill in the size of the stripe */
	if (options & MDCMD_UPDATE) {
		stripep->common.size = ms->c.un_total_blocks;
		for (row = 0; (row < nrow); ++row) {
			stripep->rows.rows_val[row].row_size =
			    ms->un_row[row].un_blocks;
		}
	}

	if (stripe_geom(stripep, ms, ep) != 0) {
		/*
		 * If the device is being truncated then only allow this
		 * if the user is aware (using the -f option) or they
		 * are in a recovery/complete build situation (using the -a
		 * option).
		 */
		if ((mdiserror(ep, MDE_STRIPE_TRUNC_SINGLE) ||
		    mdiserror(ep, MDE_STRIPE_TRUNC_MULTIPLE)) &&
		    (force || doall)) {
			md_eprintf(dgettext(TEXT_DOMAIN,
"%s: WARNING: This form of metainit is not recommended.\n"
"The stripe is truncating the size of the underlying device.\n"
"Please see ERRORS in metainit(1M) for additional information.\n"),
			    stripenp->cname);
			mdclrerror(ep);
		} else {
			goto out;
		}
	}

	create_flag = meta_check_devicesize(ms->c.un_total_blocks);

	/* if we're not doing anything, return success */
	if (! (options & MDCMD_DOIT)) {
		rval = 0;	/* success */
		goto out;
	}

	/* create stripe */
	(void) memset(&set_params, 0, sizeof (set_params));

	/* did the user tell us to generate a large device? */
	if (create_flag == MD_CRO_64BIT) {
		ms->c.un_revision |= MD_64BIT_META_DEV;
		set_params.options = MD_CRO_64BIT;
	} else {
		ms->c.un_revision &= ~MD_64BIT_META_DEV;
		set_params.options = MD_CRO_32BIT;
	}

	set_params.mnum = MD_SID(ms);
	set_params.size = ms->c.un_size;
	set_params.mdp = (uintptr_t)ms;
	MD_SETDRIVERNAME(&set_params, MD_STRIPE, MD_MIN2SET(set_params.mnum));
	if (metaioctl(MD_IOCSET, &set_params, &set_params.mde,
	    stripenp->cname) != 0) {
		(void) mdstealerror(ep, &set_params.mde);
		goto out;
	}
	rval = 0;	/* success */

	/* cleanup, return success */
out:
	Free(ms);
	if (rval != 0) {
		(void) del_key_names(sp, keynlp, NULL);
	}

	metafreenamelist(keynlp);
	if ((rval == 0) && (options & MDCMD_DOIT)) {
		if (invalidate_components(sp, stripenp, ep) != 0)
			rval = -1;
		meta_invalidate_name(stripenp);
	}
	return (rval);
}

/*
 * initialize stripe
 * NOTE: this functions is metainit(1m)'s command line parser!
 */
int
meta_init_stripe(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*uname = argv[0];
	mdname_t	*stripenp = NULL;
	int		old_optind;
	int		c;
	md_stripe_t	*stripep = NULL;
	uint_t		nrow, row;
	int		rval = -1;

	/* get stripe name */
	assert(argc > 0);
	if (argc < 1)
		goto syntax;

	if ((stripenp = metaname(spp, uname, META_DEVICE, ep)) == NULL)
		goto out;
	assert(*spp != NULL);
	uname = stripenp->cname;
	if (metachkmeta(stripenp, ep) != 0)
		goto out;

	if (!(options & MDCMD_NOLOCK)) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep))
			goto out;

		if (meta_check_ownership(*spp, ep) != 0)
			goto out;
	}

	/* see if it exists already */
	if (metagetmiscname(stripenp, ep) != NULL) {
		(void) mdmderror(ep, MDE_UNIT_ALREADY_SETUP,
		    meta_getminor(stripenp->dev), uname);
		goto out;
	} else if (! mdismderror(ep, MDE_UNIT_NOT_SETUP)) {
		goto out;
	} else {
		mdclrerror(ep);
	}
	--argc, ++argv;

	/* parse general options */
	optind = 0;
	opterr = 0;
	if (getopt(argc, argv, "") != -1)
		goto options;

	/* allocate stripe */
	stripep = Zalloc(sizeof (*stripep));

	/* setup common */
	stripep->common.namep = stripenp;
	stripep->common.type = MD_DEVICE;

	/* allocate and parse rows */
	if (argc < 1) {
		(void) mdmderror(ep, MDE_NROWS, meta_getminor(stripenp->dev),
		    uname);
		goto out;
	} else if ((sscanf(argv[0], "%u", &nrow) != 1) || ((int)nrow < 0)) {
		goto syntax;
	} else if (nrow < 1) {
		(void) mdmderror(ep, MDE_NROWS, meta_getminor(stripenp->dev),
		    uname);
		goto out;
	}
	--argc, ++argv;
	stripep->rows.rows_len = nrow;
	stripep->rows.rows_val =
	    Zalloc(nrow * sizeof (*stripep->rows.rows_val));
	for (row = 0; (row < nrow); ++row) {
		md_row_t	*mdr = &stripep->rows.rows_val[row];
		uint_t		ncomp, comp;

		/* allocate and parse components */
		if (argc < 1) {
			(void) mdmderror(ep, MDE_NROWS,
			    meta_getminor(stripenp->dev), uname);
			goto out;
		} else if ((sscanf(argv[0], "%u", &ncomp) != 1) ||
		    ((int)ncomp < 0)) {
			goto syntax;
		} else if (ncomp < 1) {
			(void) mdmderror(ep, MDE_NCOMPS,
			    meta_getminor(stripenp->dev), uname);
			goto out;
		}
		--argc, ++argv;
		mdr->comps.comps_len = ncomp;
		mdr->comps.comps_val =
		    Zalloc(ncomp * sizeof (*mdr->comps.comps_val));
		for (comp = 0; (comp < ncomp); ++comp) {
			md_comp_t	*mdc = &mdr->comps.comps_val[comp];
			mdname_t	*compnp;

			/* parse component name */
			if (argc < 1) {
				(void) mdmderror(ep, MDE_NCOMPS,
				    meta_getminor(stripenp->dev), uname);
				goto out;
			}
			if ((compnp = metaname(spp, argv[0], UNKNOWN,
			    ep)) == NULL) {
				goto out;
			}
			/* check for soft partition */
			if (meta_sp_issp(*spp, compnp, ep) != 0) {
				/* check disk */
				if (metachkcomp(compnp, ep) != 0) {
					goto out;
				}
			}
			mdc->compnamep = compnp;
			--argc, ++argv;
		}

		/* parse row options */
		old_optind = optind = 0;
		opterr = 0;
		while ((c = getopt(argc, argv, "i:")) != -1) {
			switch (c) {
			case 'i':
				if (parse_interlace(uname, optarg,
				    &mdr->interlace, ep) != 0) {
					goto out;
				}
				if (meta_stripe_check_interlace(mdr->interlace,
				    uname, ep))
					goto out;
				break;

			default:
				optind = old_optind;	/* bomb out later */
				goto done_row_opts;
			}
			old_optind = optind;
		}
done_row_opts:
		argc -= optind;
		argv += optind;
	}

	/* parse stripe options */
	old_optind = optind = 0;
	opterr = 0;
	while ((c = getopt(argc, argv, "h:")) != -1) {
		switch (c) {
		case 'h':
			if ((stripep->hspnamep = metahspname(spp, optarg,
			    ep)) == NULL) {
				goto out;
			}

			/*
			 * Get out if the specified hotspare pool really
			 * doesn't exist.
			 */
			if (stripep->hspnamep->hsp == MD_HSP_NONE) {
				(void) mdhsperror(ep, MDE_INVAL_HSP,
				    stripep->hspnamep->hsp, optarg);
				goto out;
			}
			break;

		default:
			argc += old_optind;
			argv += old_optind;
			goto options;
		}
		old_optind = optind;
	}
	argc -= optind;
	argv += optind;

	/* we should be at the end */
	if (argc != 0)
		goto syntax;

	/* create stripe */
	if (meta_create_stripe(*spp, stripep, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Concat/Stripe is setup\n"),
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
	if (stripep != NULL)
		meta_free_stripe(stripep);
	return (rval);
}

/*
 * reset stripes
 */
int
meta_stripe_reset(
	mdsetname_t	*sp,
	mdname_t	*stripenp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	int		rval = -1;
	int		row, comp;

	/* should have same set */
	assert(sp != NULL);
	assert((stripenp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(stripenp->dev))));

	/* reset all stripes */
	if (stripenp == NULL) {
		mdnamelist_t	*stripenlp = NULL;
		mdnamelist_t	*p;

		/* for each stripe */
		rval = 0;
		if (meta_get_stripe_names(sp, &stripenlp, 0, ep) < 0)
			return (-1);
		for (p = stripenlp; (p != NULL); p = p->next) {
			/* reset stripe */
			stripenp = p->namep;

			/*
			 * If this is a multi-node set, we send a series
			 * of individual metaclear commands.
			 */
			if (meta_is_mn_set(sp, ep)) {
				if (meta_mn_send_metaclear_command(sp,
				    stripenp->cname, options, 0, ep) != 0) {
					rval = -1;
					break;
				}
			} else {
				if (meta_stripe_reset(sp, stripenp,
				    options, ep) != 0) {
					rval = -1;
					break;
				}
			}
		}

		/* cleanup, return success */
		metafreenamelist(stripenlp);
		return (rval);
	}

	/* check name */
	if (metachkmeta(stripenp, ep) != 0)
		return (-1);

	/* get unit structure */
	if ((stripep = meta_get_stripe(sp, stripenp, ep)) == NULL)
		return (-1);

	/* make sure nobody owns us */
	if (MD_HAS_PARENT(stripep->common.parent)) {
		return (mdmderror(ep, MDE_IN_USE, meta_getminor(stripenp->dev),
		    stripenp->cname));
	}

	/* clear subdevices cache */
	if (invalidate_components(sp, stripenp, ep) != 0)
		return (-1);

	/* clear metadevice */
	if (meta_reset(sp, stripenp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Concat/Stripe is cleared\n"),
		    stripenp->cname);
		(void) fflush(stdout);
	}

	/* clear subdevices */
	if (! (options & MDCMD_RECURSE))
		goto out;

	for (row = 0; (row < stripep->rows.rows_len); ++row) {
		md_row_t	*rp = &stripep->rows.rows_val[row];
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;

			/* only recurse on metadevices */
			if (! metaismeta(compnp))
				continue;

			if (meta_reset_by_name(sp, compnp, options, ep) != 0)
				rval = -1;
		}
	}

	/* cleanup, return success */
out:
	meta_invalidate_name(stripenp);
	return (rval);
}

/*
 * reports TRUE if any stripe component is in error
 */
int
meta_stripe_anycomp_is_err(mdsetname_t *sp, mdnamelist_t *stripe_names)
{
	mdnamelist_t	*nlp;
	md_error_t	  status	= mdnullerror;
	md_error_t	 *ep		= &status;
	int		  any_errs	= FALSE;

	for (nlp = stripe_names; nlp; nlp = nlp->next) {
		md_stripe_t	*stripep;
		int		 row;

		if ((stripep = meta_get_stripe(sp, nlp->namep, ep)) == NULL) {
			any_errs |= TRUE;
			goto out;
		}

		for (row = 0; row < stripep->rows.rows_len; ++row) {
			md_row_t	*rp	= &stripep->rows.rows_val[row];
			uint_t		 comp;

			for (comp = 0; comp < rp->comps.comps_len; ++comp) {
				md_comp_t *cp	= &rp->comps.comps_val[comp];

				if (cp->state != CS_OKAY) {
					any_errs |= TRUE;
					goto out;
				}
			}
		}
	}
out:
	if (!mdisok(ep))
		mdclrerror(ep);

	return (any_errs);
}

int
meta_stripe_check_component(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_dev64_t	mydevs,
	md_error_t	*ep
)
{
	md_stripe_t	*stripe;
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
	int	cnt, i;
	int	rval = -1;

	(void) memset(&nm, '\0', sizeof (nm));
	if ((stripe = meta_get_stripe_common(sp, np, 0, ep)) == NULL)
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

	for (cnt = 0, i = 0; i < stripe->rows.rows_len; i++) {
		md_row_t	*rp = &stripe->rows.rows_val[i];
		uint_t	comp;
		for (comp = 0; (comp < rp->comps.comps_len); ++comp) {
			md_comp_t	*cp = &rp->comps.comps_val[comp];
			mdname_t	*compnp = cp->compnamep;

			if (mydevs == mydev[cnt]) {
				/* Get the devname from the name space. */
				if ((devname = meta_getnmentbydev(sp->setno,
				    sideno, compnp->dev, NULL, NULL,
				    &key, ep)) == NULL) {
					goto out;
				}

				if (compnp->dev != meta_getminor(mydev[cnt])) {
					/*
					 * The minor numbers are different.
					 * Update the namespace with the
					 * information from the component.
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

					if (meta_update_namespace(sp->setno,
					    sideno, ctd_name, mydev[i],
					    key, pname, ep) != 0) {
						goto out;
					}
				}
				rval = 0;
				break;
			} /*  End of if (mydevs == mydev[i]) */
			cnt++;
		} /* End of second for loop */
	} /* End of first for loop */
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
