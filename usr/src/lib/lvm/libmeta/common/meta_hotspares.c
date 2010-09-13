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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * hotspares utilities
 */

#include <meta.h>
#include <sys/lvm/md_hotspares.h>
#include <sys/lvm/md_convert.h>

/*
 * FUNCTION:	meta_get_hsp_names()
 * INPUT:	sp	- the set name to get hotspares from
 *		options	- options from the command line
 * OUTPUT:	hspnlpp	- list of all hotspare names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	returns a list of all hotspares in the metadb
 *		for all devices in the specified set
 */
/*ARGSUSED*/
int
meta_get_hsp_names(
	mdsetname_t	*sp,
	mdhspnamelist_t	**hspnlpp,
	int		options,
	md_error_t	*ep
)
{
	md_i_getnum_t	gn;		/* MD_IOCGET_NUM params */
	minor_t		*minors = NULL;
	minor_t		*m_ptr;
	int		i;

	/* we must have a set */
	assert(sp != NULL);

	(void) memset(&gn, 0, sizeof (gn));
	MD_SETDRIVERNAME(&gn, MD_HOTSPARES, sp->setno);

	/* get number of devices */
	if (metaioctl(MD_IOCGET_NUM, &gn, &gn.mde, NULL) != 0) {
		if (mdiserror(&gn.mde, MDE_UNIT_NOT_FOUND)) {
			mdclrerror(&gn.mde);
		} else {
			(void) mdstealerror(ep, &gn.mde);
			return (-1);
		}
	}

	if (gn.size > 0) {
		/* malloc minor number buffer to be filled by ioctl */
		if ((minors = (minor_t *)malloc(
				gn.size * sizeof (minor_t))) == 0) {
			return (ENOMEM);
		}
		gn.minors = (uintptr_t)minors;
		if (metaioctl(MD_IOCGET_NUM, &gn, &gn.mde, NULL) != 0) {
			(void) mdstealerror(ep, &gn.mde);
			free(minors);
			return (-1);
		}
		m_ptr = minors;
		for (i = 0; i < gn.size; i++) {
			mdhspname_t	*hspnp;


			/* get name */
			if ((hspnp = metahsphspname(&sp, *m_ptr, ep))
					== NULL)
				goto out;

			/* append to list */
			(void) metahspnamelist_append(hspnlpp, hspnp);

			/* next device */
			m_ptr++;
		}
		free(minors);
	}
	return (gn.size);

out:
	if (minors != NULL)
		free(minors);
	metafreehspnamelist(*hspnlpp);
	*hspnlpp = NULL;
	return (-1);
}

/*
 * get information of a specific hotspare pool from driver
 */
static get_hsp_t *
get_hspinfo(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	md_error_t	*ep
)
{
	md_i_get_t	mig;

	/* should have a set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* get size of unit structure */
	(void) memset(&mig, 0, sizeof (mig));
	MD_SETDRIVERNAME(&mig, MD_HOTSPARES, sp->setno);
	mig.id = hspnp->hsp;
	if (metaioctl(MD_IOCGET, &mig, &mig.mde, hspnp->hspname) != 0) {
		(void) mdstealerror(ep, &mig.mde);
		return (NULL);
	}

	/* get actual unit structure */
	assert(mig.size > 0);
	mig.mdp = (uintptr_t)Zalloc(mig.size);
	if (metaioctl(MD_IOCGET, &mig, &mig.mde, hspnp->hspname) != 0) {
		(void) mdstealerror(ep, &mig.mde);
		Free((void *)(uintptr_t)mig.mdp);
		return (NULL);
	}
	return ((get_hsp_t *)(uintptr_t)mig.mdp);
}

/*
 * free hotspare pool unit
 */
void
meta_free_hsp(
	md_hsp_t	*hspp
)
{
	if (hspp->hotspares.hotspares_val != NULL) {
		assert(hspp->hotspares.hotspares_len > 0);
		Free(hspp->hotspares.hotspares_val);
	}
	Free(hspp);
}

/*
 * get hotspare pool unit (common)
 */
md_hsp_t *
meta_get_hsp_common(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	int		fast,
	md_error_t	*ep
)
{
	get_hsp_t	*ghsp;
	md_hsp_t	*hspp;
	uint_t		hsi;

	/* must have set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* short circuit */
	if (hspnp->unitp != NULL)
		return (hspnp->unitp);

	/* get unit */
	if ((ghsp = get_hspinfo(sp, hspnp, ep)) == NULL)
		return (NULL);

	/* allocate hsp */
	hspp = Zalloc(sizeof (*hspp));

	/* allocate hotspares */
	hspp->hotspares.hotspares_len = ghsp->ghsp_nhotspares;

	/* if empty hotspare pool, we are done */
	if (hspp->hotspares.hotspares_len != 0)
		hspp->hotspares.hotspares_val =
		    Zalloc(hspp->hotspares.hotspares_len *
		    sizeof (*hspp->hotspares.hotspares_val));

	/* get name, refcount */
	hspp->hspnamep = hspnp;
	hspp->refcount = ghsp->ghsp_refcount;

	/* get hotspares */
	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		mdkey_t		hs_key = ghsp->ghsp_hs_keys[hsi];
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];
		get_hs_params_t	ghs;

		/* get hotspare name */
		hsp->hsnamep = metakeyname(&sp, hs_key, fast, ep);
		if (hsp->hsnamep == NULL)
			goto out;

		/* get hotspare state */
		(void) memset(&ghs, 0, sizeof (ghs));
		MD_SETDRIVERNAME(&ghs, MD_HOTSPARES, sp->setno);
		ghs.ghs_key = hs_key;
		if (metaioctl(MD_IOCGET_HS, &ghs, &ghs.mde, NULL) != 0) {
			(void) mdstealerror(ep, &ghs.mde);
			goto out;
		}
		hsp->state = ghs.ghs_state;
		hsp->size = ghs.ghs_number_blks;
		hsp->timestamp = ghs.ghs_timestamp;
		hsp->revision = ghs.ghs_revision;
	}

	/* cleanup, return success */
	Free(ghsp);
	hspnp->unitp = hspp;
	return (hspp);

	/* cleanup, return error */
out:
	Free(ghsp);
	meta_free_hsp(hspp);
	return (NULL);
}

/*
 * get hotspare pool unit
 */
md_hsp_t *
meta_get_hsp(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	md_error_t	*ep
)
{
	return (meta_get_hsp_common(sp, hspnp, 0, ep));
}

/*
 * check hotspare pool for dev
 */
static int
in_hsp(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	md_hsp_t	*hspp;
	uint_t		i;

	/* should be in the same set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* get unit */
	if ((hspp = meta_get_hsp(sp, hspnp, ep)) == NULL)
		return (-1);

	/* look in hotspares */
	for (i = 0; (i < hspp->hotspares.hotspares_len); ++i) {
		md_hs_t		*hs = &hspp->hotspares.hotspares_val[i];
		mdname_t	*hsnp = hs->hsnamep;

		/* check overlap */
		if (metaismeta(hsnp))
			continue;
		if (meta_check_overlap(hspnp->hspname, np, slblk, nblks,
		    hsnp, 0, -1, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a hotspare pool
 */
int
meta_check_inhsp(
	mdsetname_t	*sp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	mdhspnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each hotspare pool */
	if (meta_get_hsp_names(sp, &hspnlp, 0, ep) < 0)
		return (-1);
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		/* check hotspare pool */
		if (in_hsp(sp, hspnp, np, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreehspnamelist(hspnlp);
	return (rval);
}

/*
 * check hotspare
 */
int
meta_check_hotspare(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdchkopts_t	options = (MDCHK_ALLOW_HS);

	/* make sure we have a disk */
	if (metachkcomp(np, ep) != 0)
		return (-1);

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
 * print hsp
 */
static int
hsp_print(
	md_hsp_t	*hspp,
	char		*fname,
	FILE		*fp,
	md_error_t	*ep
)
{
	uint_t		hsi;
	int		rval = -1;

	/* print name */
	if (fprintf(fp, "%s", hspp->hspnamep->hspname) == EOF)
		goto out;

	/* print hotspares */
	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];

		/* print hotspare */
		/*
		 * If the path is our standard /dev/rdsk or /dev/md/rdsk
		 * then just print out the cxtxdxsx or the dx, metainit
		 * will assume the default, otherwise we need the full
		 * pathname to make sure this works as we intend.
		 */
		if ((strstr(hsp->hsnamep->rname, "/dev/rdsk") == NULL) &&
		    (strstr(hsp->hsnamep->rname, "/dev/md/rdsk") == NULL) &&
		    (strstr(hsp->hsnamep->rname, "/dev/td/") == NULL)) {
			/* not standard path, print full pathname */
			if (fprintf(fp, " %s", hsp->hsnamep->rname) == EOF)
				goto out;
		} else {
			/* standard path, just print ctd or d value */
			if (fprintf(fp, " %s", hsp->hsnamep->cname) == EOF)
				goto out;
		}
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

/*
 * hotspare state name
 */
char *
hs_state_to_name(
	md_hs_t			*hsp,
	md_timeval32_t		*tvp
)
{
	hotspare_states_t	state = hsp->state;

	/* grab time */
	if (tvp != NULL)
		*tvp = hsp->timestamp;

	switch (state) {
	case HSS_AVAILABLE:
		return (dgettext(TEXT_DOMAIN, "Available"));
	case HSS_RESERVED:
		return (dgettext(TEXT_DOMAIN, "In use"));
	case HSS_BROKEN:
		return (dgettext(TEXT_DOMAIN, "Broken"));
	case HSS_UNUSED:
	default:
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

/*
 * report hsp
 */
static int
hsp_report(
	md_hsp_t	*hspp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep,
	mdsetname_t	*sp
)
{
	uint_t		hsi;
	int		rval = -1;
	char		*devid = "";
	mdname_t	*didnp = NULL;
	uint_t		len;
	int		large_hs_dev_cnt = 0;
	int		fn_hs_dev_cnt = 0;

	if (options & PRINT_LARGEDEVICES) {
		for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
			md_hs_t	*hsp = &hspp->hotspares.hotspares_val[hsi];
			if (hsp->revision & MD_64BIT_META_DEV) {
				large_hs_dev_cnt += 1;
				if (meta_getdevs(sp, hsp->hsnamep, nlpp, ep)
				    != 0)
					goto out;
			}
		}

		if (large_hs_dev_cnt == 0) {
			rval = 0;
			goto out;
		}
	}

	if (options & PRINT_FN) {
		if (!HSP_ID_IS_FN(hspp->hspnamep->hsp)) {
			rval = 0;
			goto out;
		}
		for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
			md_hs_t	*hsp = &hspp->hotspares.hotspares_val[hsi];
			fn_hs_dev_cnt += 1;
			if (meta_getdevs(sp, hsp->hsnamep, nlpp, ep)
			    != 0)
				goto out;
		}
	}

	/* print header */
	if (hspp->hotspares.hotspares_len == 0) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: is empty\n"),
		    hspp->hspnamep->hspname) == EOF) {
			goto out;
		}
	} else if (hspp->hotspares.hotspares_len == 1) {

		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */

		len = strlen(hspp->hotspares.hotspares_val[0].hsnamep->cname);
		/*
		 * if the length is to short to print out all of the header
		 * force the matter
		 */
		len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
		len += 2;
		if (options & PRINT_LARGEDEVICES) {
			if (fprintf(fp,
			    "%s: 1 hot spare (1 big device)\n\t%-*.*s  "
			    "%-12.12s%-8.6s\t\t%s\n",
			    hspp->hspnamep->hspname, len, len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Status"),
			    dgettext(TEXT_DOMAIN, "Length"),
			    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp,
			    "%s: 1 hot spare\n\t%-*.*s %-12.12s%-8.6s\t\t%s\n",
			    hspp->hspnamep->hspname, len, len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Status"),
			    dgettext(TEXT_DOMAIN, "Length"),
			    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
				goto out;
			}
		}
	} else {
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		len = 0;
		for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
			len = max(len, strlen(hspp->
			    hotspares.hotspares_val[hsi].hsnamep->cname));
		}
		len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
		len += 2;
		if (options & PRINT_LARGEDEVICES) {
			if (fprintf(fp,
			    "%s: %u hot spares (%d big device(s))\n\t%-*.*s "
			    "%-12.12s%-8.6s\t\t%s\n",
			    hspp->hspnamep->hspname,
			    hspp->hotspares.hotspares_len,
			    large_hs_dev_cnt, len, len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Status"),
			    dgettext(TEXT_DOMAIN, "Length"),
			    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp, "%s: %u hot spares\n\t%-*.*s "
			    "%-12.12s%-8.6s\t\t%s\n",
			    hspp->hspnamep->hspname,
			    hspp->hotspares.hotspares_len, len, len,
			    dgettext(TEXT_DOMAIN, "Device"),
			    dgettext(TEXT_DOMAIN, "Status"),
			    dgettext(TEXT_DOMAIN, "Length"),
			    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
				goto out;
			}
		}
	}

	/* print hotspares */
	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];
		char		*cname = hsp->hsnamep->cname;
		char		*hs_state;
		md_timeval32_t	tv;
		char		*timep;
		ddi_devid_t	dtp;

		/* populate the key in the name_p structure */
		if ((didnp = metadevname(&sp, hsp->hsnamep->dev, ep)) == NULL) {
			return (-1);
		}

		if (options & PRINT_LARGEDEVICES) {
			if ((hsp->revision & MD_64BIT_META_DEV) == 0)
				continue;
		}
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
		/* print hotspare */
		hs_state = hs_state_to_name(hsp, &tv);
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		if (! (options & PRINT_TIMES)) {
			if (fprintf(fp,
			    "        %-*s %-12s %lld blocks\t%s\n",
			    len, cname, hs_state,
			    hsp->size, devid) == EOF) {
				goto out;
			}
		} else {
			timep = meta_print_time(&tv);

			if (fprintf(fp,
			    "        %-*s\t    %-11s %8lld blocks%s\t%s\n",
			    len, cname, hs_state,
			    hsp->size, devid, timep) == EOF) {
				goto out;
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
 * print/report hsp
 */
int
meta_hsp_print(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_hsp_t	*hspp;

	/* should have same set */
	assert(sp != NULL);
	assert(hspnp == NULL || hspnp->hsp == MD_HSP_NONE ||
	    sp->setno == HSP_SET(hspnp->hsp));

	/* print all hsps */
	if (hspnp == NULL) {
		mdhspnamelist_t	*hspnlp = NULL;
		mdhspnamelist_t	*p;
		int		cnt;
		int		rval = 0;

		if ((cnt = meta_get_hsp_names(sp, &hspnlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recurse */
		for (p = hspnlp; (p != NULL); p = p->next) {
			mdhspname_t	*hspnp = p->hspnamep;

			if (meta_hsp_print(sp, hspnp, nlpp, fname, fp,
			    options, ep) != 0)
				rval = -1;
		}

		/* cleanup, return success */
		metafreehspnamelist(hspnlp);
		return (rval);
	}

	/* get unit structure */
	if ((hspp = meta_get_hsp_common(sp, hspnp,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* print appropriate detail */
	if (options & PRINT_SHORT)
		return (hsp_print(hspp, fname, fp, ep));
	else
		return (hsp_report(hspp, nlpp, fname, fp, options, ep, sp));
}

/*
 * check for valid hotspare pool
 */
int
metachkhsp(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	md_error_t	*ep
)
{
	if (meta_get_hsp(sp, hspnp, ep) == NULL)
		return (-1);
	return (0);
}

/*
 * invalidate hotspare pool info
 */
void
meta_invalidate_hsp(
	mdhspname_t	*hspnp
)
{
	md_hsp_t	*hspp = hspnp->unitp;

	/* free it up */
	if (hspp == NULL)
		return;
	meta_free_hsp(hspp);

	/* clear cache */
	hspnp->unitp = NULL;
}

/*
 * FUNCTION:	del_hsp_name_mn_sides()
 * INPUT:	sp	- set name
 *		curside	- side of this node
 *		key	- key of records to delete
 * OUTPUT:	ep	- error information
 * RETURNS:	none.
 * PURPOSE:	There are name records for each side in a set.  This
 *		function deletes the records associated with the specified
 *		key for all sides except curside.  This function is used
 *		when the set is a multinode set.
 */
static void
del_hsp_name_mn_sides(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	side_t		curside,
	mdkey_t		key,
	md_error_t	*ep
)
{
	md_error_t	first_error = MDNULLERROR;
	int		error_seen = FALSE;
	md_mnnode_desc	*nd;

	for (nd = sd->sd_nodelist; nd; nd = nd->nd_next) {
		if (nd->nd_nodeid == curside)
			continue;
		if (del_name(sp, nd->nd_nodeid, key, &first_error) == -1) {
			if (error_seen == FALSE) {
				error_seen = TRUE;
				(void) mdstealerror(ep, &first_error);
			}
		}
	}
}

/*
 * FUNCTION:	del_hsp_name_trad_sides()
 * INPUT:	sp	- set name
 *		curside	- side of this node
 *		key	- key of records to delete
 * OUTPUT:	ep	- error information
 * RETURNS:	none.
 * PURPOSE:	There are name records for each side in a set.  This
 *		function deletes the records associated with the specified
 *		key for all sides except curside.  This function is used
 *		when the set is a traditional set.
 */
static void
del_hsp_name_trad_sides(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	side_t		curside,
	mdkey_t		key,
	md_error_t	*ep
)
{
	int		error_seen = FALSE;
	md_error_t	first_error = MDNULLERROR;
	int		i;

	for (i = 0; i < MD_MAXSIDES; i++) {
		if (i == curside)
			continue;
		if (sd->sd_nodes[i][0] != '\0') {
			if (del_name(sp, i, key, &first_error) == -1) {
				if (error_seen == FALSE) {
					error_seen = TRUE;
					(void) mdstealerror(ep, &first_error);
				}
			}
		}
	}
}

/*
 * FUNCTION:	del_hsp_keys()
 * INPUT:	sp	- set name
 *		hspid	- ID of records to delete
 * OUTPUT:	ep	- error information
 * RETURNS:	0	- success
 *		-1	- error
 * PURPOSE:	Remove the NM records associated with hspid from all sides
 *		of the set.  Missing records are not considered to be an
 *		error.  The key associated with the current side is removed
 *		last.
 *
 *		This function is very similar to del_key_name(), except it
 *		does not require any device look up.  This is because the
 *		hot spare pool is not a device.
 */
static int
del_hsp_keys(mdsetname_t *sp, hsp_t hspid, md_error_t *ep)
{
	md_error_t	first_error = MDNULLERROR;
	mdkey_t		key = HSP_ID_TO_KEY(hspid);
	md_set_desc	*sd;
	side_t		thisside;	/* Side # of this node. */

	/*
	 * If there is no key, this means that the hot spare was created
	 * before the introduction of friendly names.  Thus, the is no NM
	 * record and nothing for us to do in this function.
	 */
	if (key == MD_KEYBAD)
		return (0);

	/* Find our current side */
	mdclrerror(ep);
	thisside = getmyside(sp, ep);
	if (! mdisok(ep))
		return (-1);

	/*
	 * If not the local set, we need to process the non-local sides
	 * first.
	 */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if (MD_MNSET_DESC(sd)) {
			/* Multinode set.  Sides are in a linked list. */
			del_hsp_name_mn_sides(sp, sd, thisside, key,
				&first_error);
		} else {
			/* Sides are in an array. */
			del_hsp_name_trad_sides(sp, sd, thisside, key,
				&first_error);
		}
	}

	/* Now delete the name for the current side. */
	(void) del_name(sp, thisside, key, ep);
	if (! mdisok(&first_error))
		(void) mdstealerror(ep, &first_error);
	return (mdisok(ep) ? 0 : -1);
}

/*
 * FUNCTION:	add_hsp_name_mn_sides()
 * INPUT:	sp	- set name
 *		curside	- side number for this node
 *		key	- key to use for the name record
 *		hsp_name - name of the hot spare
 * OUTPUT:	ep	- error information
 * RETURNS:	0 indicates success, and -1 indicates failure.
 * PURPOSE:	Once the name record has been added for the current side,
 *		this function adds the record to the remaining sides.  This
 *		function is to be used when the set is a multinode set.
 *		The side designated by curside will be ignored when adding
 *		records.
 */
static int
add_hsp_name_mn_sides(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	side_t		curside,
	mdkey_t		key,
	char		*hsp_name,
	md_error_t	*ep
)
{
	md_mnnode_desc	*nd;

	for (nd = sd->sd_nodelist; nd; nd = nd->nd_next) {
		if (nd->nd_nodeid == curside)
			continue;
		if (add_name(sp, nd->nd_nodeid, key, MD_HOTSPARES,
			minor(NODEV), hsp_name, NULL, NULL, ep) == -1) {
			return (-1);
		}
	}
	return (0);
}

/*
 * FUNCTION:	add_hsp_name_trad_sides()
 * INPUT:	sp	- set name
 *		curside	- side number for this node
 *		key	- key to use for the name record
 *		hsp_name - name of the hot spare
 * OUTPUT:	ep	- error information
 * RETURNS:	0 indicates success, and -1 indicates failure.
 * PURPOSE:	Once the name record has been added for the current side,
 *		this function adds the record to the remaining sides.  This
 *		function is to be used when the set is a traditional set.
 *		The side designated by curside will be ignored when adding
 *		records.
 */
static int
add_hsp_name_trad_sides(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	side_t		curside,
	mdkey_t		key,
	char		*hsp_name,
	md_error_t	*ep
)
{
	int		i;

	for (i = 0; i < MD_MAXSIDES; i++) {
		if (i == curside)
			continue;
		if (sd->sd_nodes[i][0] != '\0') {
			if (add_name(sp, i, key, MD_HOTSPARES, minor(NODEV),
				hsp_name, NULL, NULL, ep) == -1) {
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * FUNCTION:	add_hsp_name()
 * INPUT:	sp	- Name of the set containing the hsp
 *		hsp_name - Hot spare pool name to be added
 * OUTPUT:	ep	- Error information
 * RETURNS:	If successful the key of the newly added record is
 *		returned.  MD_KEYBAD is returned to indicate a failure.
 * PURPOSE:	This function creates a new NM record containing the name
 *		of the hotspare pool.  A record containing the name is
 *		added to each active side, but the record is added first to
 *		the current side.  This function is modeled on
 *		add_key_name() in meta_namespace.  The difference is that
 *		there is no device associated with a hot spare pool
 */
static hsp_t
add_hsp_name(
	mdsetname_t	*sp,
	char		*hsp_name,
	md_error_t	*ep
)
{
	md_error_t	ignore_error = MDNULLERROR;
	mdkey_t		key;
	md_set_desc	*sd;
	side_t		thisside;	/* Side # of this node. */

	if (sp == NULL) {
		(void) mderror(ep, MDE_NO_SET, NULL);
		return (MD_KEYBAD);
	}
	if (hsp_name == NULL) {
		(void) mderror(ep, MDE_INVAL_HSOP, NULL);
		return (MD_KEYBAD);
	}

	mdclrerror(ep);
	thisside = getmyside(sp, ep);
	if (! mdisok(ep))
		return (MD_HSPID_WILD);

	/* First add the record for the side of the current node. */
	key = add_name(sp, thisside, MD_KEYWILD, MD_HOTSPARES, minor(NODEV),
		hsp_name, NULL, NULL, ep);
	if (key == -1) {
		goto cleanup;
	}

	/* Make sure that we can use the key */
	if (!HSP_KEY_OK(key)) {
		(void) mdhsperror(ep, MDE_HSP_CREATE_FAILURE, MD_HSPID_WILD,
			hsp_name);
		goto cleanup;
	}

	/*
	 * Now that we have a key, we will use it to add a record to the
	 * rest of the sides in the set.  For multinode sets, the sides are
	 * in a linked list that is anchored on the set descriptor.  For
	 * traditional sets the side information is in an array in the set
	 * descriptor.
	 */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			goto cleanup;
		}
		if (MD_MNSET_DESC(sd)) {
			/* Multinode set.  Sides are in linked list. */
			if (add_hsp_name_mn_sides(sp, sd, thisside, key,
				hsp_name, ep) == -1) {
				goto cleanup;
			}
		} else {
			/* Traditional set.  Sides are in an array. */
			if (add_hsp_name_trad_sides(sp, sd, thisside, key,
				hsp_name, ep) == -1) {
				goto cleanup;
			}
		}
	}

	return (KEY_TO_HSP_ID(sp->setno, key));

cleanup:
	/* Get rid records that we added. */
	(void) del_hsp_keys(sp, KEY_TO_HSP_ID(sp->setno, key), &ignore_error);
	return (MD_HSPID_WILD);
}

/*
 * add hotspares and/or hotspare pool
 */
int
meta_hs_add(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdnamelist_t	*hsnlp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_error_t	ignore_error = MDNULLERROR;
	mdnamelist_t	*p;
	set_hs_params_t	shs;
	side_t		thisside;

	/* should have a set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* clear cache */
	meta_invalidate_hsp(hspnp);

	/* setup hotspare pool info */
	(void) memset(&shs, 0, sizeof (shs));
	shs.shs_cmd = ADD_HOT_SPARE;
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);

	/* Get key for hot spare pool name record. */
	if (options & MDCMD_DOIT) {
		/* First see if the name record already exists. */
		mdclrerror(ep);
		thisside = getmyside(sp, ep);
		if (! mdisok(ep))
			return (-1);
		shs.shs_hot_spare_pool =
			meta_gethspnmentbyname(sp->setno, thisside,
				hspnp->hspname, ep);
		if (! mdisok(ep)) {
			/*
			 * If the error is ENOENT, then we will create a
			 * hot spare pool name records.  For other types of
			 * errors, however, we'll bail out.
			 */
			if (! mdissyserror(ep, ENOENT))
				return (-1);
			mdclrerror(ep);
			/* make sure that the name isn't already in use */
			if (is_existing_metadevice(sp, hspnp->hspname))
				return (mderror(ep, MDE_NAME_IN_USE,
					hspnp->hspname));
			if ((shs.shs_hot_spare_pool =
				add_hsp_name(sp, hspnp->hspname, ep)) ==
				MD_HSPID_WILD) {
				return (-1);
			}
		}
	}

	/* add empty hotspare pool */
	if (hsnlp == NULL) {
		shs.shs_options = HS_OPT_POOL;
		/* If DOIT is not set, it's a dryrun */
		if ((options & MDCMD_DOIT) == 0) {
			shs.shs_options |= HS_OPT_DRYRUN;
		}
		if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde,
			hspnp->hspname) != 0) {
			if (options & MDCMD_DOIT) {
				(void) del_hsp_keys(sp,
					shs.shs_hot_spare_pool,
					&ignore_error);
			}
			return (mdstealerror(ep, &shs.mde));
		}
		goto success;
	}

	/* add hotspares */
	shs.shs_options = HS_OPT_NONE;
	/* If DOIT is not set, it's a dryrun */
	if ((options & MDCMD_DOIT) == 0) {
		shs.shs_options |= HS_OPT_DRYRUN;
	}
	for (p = hsnlp; (p != NULL); p = p->next) {
		mdname_t	*hsnp = p->namep;
		diskaddr_t	size, label, start_blk;

		/* should be in same set */
		assert(hspnp->hsp == MD_HSP_NONE ||
		    sp->setno == HSP_SET(hspnp->hsp));

		/* check it out */
		if (meta_check_hotspare(sp, hsnp, ep) != 0)
			return (-1);
		if ((size = metagetsize(hsnp, ep)) == MD_DISKADDR_ERROR)
			return (-1);
		else if (size == 0)
			return (mdsyserror(ep, ENOSPC, hsnp->cname));
		if ((label = metagetlabel(hsnp, ep)) == MD_DISKADDR_ERROR)
			return (-1);
		if ((start_blk = metagetstart(sp, hsnp, ep))
		    == MD_DISKADDR_ERROR)
			return (-1);

		shs.shs_size_option = meta_check_devicesize(size);

		/* In dryrun mode (DOIT not set) we must not alter the mddb */
		if (options & MDCMD_DOIT) {
			/* store name in namespace */
			if (add_key_name(sp, hsnp, NULL, ep) != 0)
				return (-1);
		}

		/* add hotspare and/or hotspare pool */
		shs.shs_component_old = hsnp->dev;
		shs.shs_start_blk = start_blk;
		shs.shs_has_label = ((label > 0) ? 1 : 0);
		shs.shs_number_blks = size;
		shs.shs_key_old = hsnp->key;
		if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde, NULL) != 0) {
			if ((options & MDCMD_DOIT) &&
			    (shs.shs_options != HS_OPT_POOL)) {
				(void) del_key_name(sp, hsnp, ep);
			}
			return (mdstealerror(ep, &shs.mde));
		}
	}

	/* print success message */
success:
	if (options & MDCMD_PRINT) {
		if ((options & MDCMD_INIT) || (hsnlp == NULL)) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspare pool is setup\n"),
			    hspnp->hspname);
		} else if (hsnlp->next == NULL) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspare is added\n"),
			    hspnp->hspname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspares are added\n"),
			    hspnp->hspname);
		}
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * FUNCTION:	meta_hsp_delete()
 * INPUT:	sp	- Name of the set containing the hsp
 *		hspnp	- Hot spare pool name information
 *		options	- Options from command line
 * OUTPUT:	ep	- Error information
 * RETURNS:	0 on success and -1 on failure.
 * PURPOSE:	Common code to delete an empty hot spare pool.
 */
static int
meta_hsp_delete(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	set_hs_params_t	shs;

	/* setup hotspare pool info */
	(void) memset(&shs, 0, sizeof (shs));
	shs.shs_hot_spare_pool = hspnp->hsp;
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);
	shs.shs_cmd = DELETE_HOT_SPARE;
	shs.shs_options = HS_OPT_POOL;
	/* If DOIT is not set, it's a dryrun */
	if ((options & MDCMD_DOIT) == 0) {
		shs.shs_options |= HS_OPT_DRYRUN;
	}

	/* Remove hsp record. */
	if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde,
	    hspnp->hspname) != 0)
		return (mdstealerror(ep, &shs.mde));

	/* Get rid of hsp NM records */
	if ((options & MDCMD_DOIT) &&
		(del_hsp_keys(sp, hspnp->hsp, ep) == -1)) {
		return (-1);
	}
	return (0);
}

/*
 * delete hotspares from pool
 */
int
meta_hs_delete(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdnamelist_t	*hsnlp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdnamelist_t	*p;
	set_hs_params_t	shs;

	/* should have a set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* clear cache */
	meta_invalidate_hsp(hspnp);

	/* setup hotspare pool info */
	(void) memset(&shs, 0, sizeof (shs));
	shs.shs_hot_spare_pool = hspnp->hsp;
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);
	shs.shs_cmd = DELETE_HOT_SPARE;

	/* delete empty hotspare pool */
	if (hsnlp == NULL) {
		if (meta_hsp_delete(sp, hspnp, options, ep) != 0)
			return (-1);
		goto success;
	}

	/* delete hotspares */
	shs.shs_options = HS_OPT_NONE;
	/* If DOIT is not set, it's a dryrun */
	if ((options & MDCMD_DOIT) == 0) {
		shs.shs_options |= HS_OPT_DRYRUN;
	}
	for (p = hsnlp; (p != NULL); p = p->next) {
		mdname_t	*hsnp = p->namep;

		/* should be in same set */
		assert(hspnp->hsp == MD_HSP_NONE ||
		    sp->setno == HSP_SET(hspnp->hsp));

		/* delete hotspare */
		shs.shs_component_old = hsnp->dev;
		meta_invalidate_name(hsnp);
		if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde, hsnp->cname) != 0)
			return (mdstealerror(ep, &shs.mde));
	}

	/* print success message */
success:
	if (options & MDCMD_PRINT) {
		if (hsnlp == NULL) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspare pool is cleared\n"),
			    hspnp->hspname);
		} else if (hsnlp->next == NULL) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspare is deleted\n"),
			    hspnp->hspname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Hotspares are deleted\n"),
			    hspnp->hspname);
		}
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * replace hotspare in pool
 */
int
meta_hs_replace(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdname_t	*oldnp,
	mdname_t	*newnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	set_hs_params_t	shs;
	diskaddr_t	size, label, start_blk;
	md_dev64_t	old_dev, new_dev;
	diskaddr_t	new_start_blk, new_end_blk;
	int		rebind;
	char		*new_devidp = NULL;
	int		ret;
	md_set_desc	*sd;

	/* should be in same set */
	assert(sp != NULL);
	assert(hspnp->hsp == MD_HSP_NONE || sp->setno == HSP_SET(hspnp->hsp));

	/* save new binding incase this is a rebind where oldnp==newnp */
	new_dev = newnp->dev;
	new_start_blk = newnp->start_blk;
	new_end_blk = newnp->end_blk;

	/* invalidate, then get the hotspare (fill in oldnp from metadb) */
	meta_invalidate_hsp(hspnp);
	if (meta_get_hsp(sp, hspnp, ep) == NULL)
		return (-1);

	/* the old device binding is now established */
	if ((old_dev = oldnp->dev) == NODEV64)
		return (mdsyserror(ep, ENODEV, oldnp->cname));

	/*
	 * check for the case where oldnp and newnp indicate the same
	 * device, but the dev_t of the device has changed between old
	 * and new.  This is called a rebind.  On entry the dev_t
	 * represents the new device binding determined from the
	 * filesystem (meta_getdev). After calling meta_get_hsp
	 * oldnp (and maybe newnp if this is a rebind) is updated based
	 * to the old binding from the metadb (done by metakeyname).
	 */
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
	 * Save a copy of the devid associated with the new disk, the reason
	 * is that the meta_check_hotspare() call could cause the devid to
	 * be changed to that of the devid that is currently stored in the
	 * replica namespace for the disk in question. This devid could be
	 * stale if we are replacing the disk. The function that overwrites
	 * the devid is dr2drivedesc().
	 */
	if (newnp->drivenamep->devid != NULL)
		new_devidp = Strdup(newnp->drivenamep->devid);

	/* if it's a multi-node diskset clear new_devidp */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			Free(new_devidp);
			return (-1);
		}
		if (MD_MNSET_DESC(sd)) {
			Free(new_devidp);
			new_devidp = NULL;
		}
	}

	/* check it out */
	if (meta_check_hotspare(sp, newnp, ep) != 0) {
		if ((! rebind) || (! mdisuseerror(ep, MDE_ALREADY))) {
			Free(new_devidp);
			return (-1);
		}
		mdclrerror(ep);
	}
	if ((size = metagetsize(newnp, ep)) == MD_DISKADDR_ERROR) {
		Free(new_devidp);
		return (-1);
	}
	if ((label = metagetlabel(newnp, ep)) == MD_DISKADDR_ERROR) {
		Free(new_devidp);
		return (-1);
	}
	if ((start_blk = metagetstart(sp, newnp, ep)) == MD_DISKADDR_ERROR) {
		Free(new_devidp);
		return (-1);
	}
	if (start_blk >= size) {
		(void) mdsyserror(ep, ENOSPC, newnp->cname);
		Free(new_devidp);
		return (-1);
	}

	/*
	 * Copy back the saved devid.
	 */
	Free(newnp->drivenamep->devid);
	if (new_devidp != NULL) {
		newnp->drivenamep->devid = new_devidp;
		new_devidp = NULL;
	}

	/* In dryrun mode (DOIT not set) we must not alter the mddb */
	if (options & MDCMD_DOIT) {
		/* store name in namespace */
		if (add_key_name(sp, newnp, NULL, ep) != 0)
			return (-1);
	}

	if (rebind && !metaislocalset(sp)) {
		/*
		 * We are 'rebind'ing a disk that is in a diskset so as well
		 * as updating the diskset's namespace the local set needs
		 * to be updated because it also contains a reference to the
		 * disk in question.
		 */
		ret = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET, newnp->cname,
		    ep);

		if (ret != METADEVADM_SUCCESS) {
			md_error_t	xep = mdnullerror;

			/*
			 * In dryrun mode (DOIT not set) we must not alter
			 * the mddb
			 */
			if (options & MDCMD_DOIT) {
				(void) del_key_name(sp, newnp, &xep);
				mdclrerror(&xep);
				return (-1);
			}
		}
	}

	/* replace hotspare */
	(void) memset(&shs, 0, sizeof (shs));

	shs.shs_size_option = meta_check_devicesize(size);

	shs.shs_cmd = REPLACE_HOT_SPARE;
	shs.shs_hot_spare_pool = hspnp->hsp;
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);
	shs.shs_component_old = old_dev;
	shs.shs_options = HS_OPT_NONE;
	/* If DOIT is not set, it's a dryrun */
	if ((options & MDCMD_DOIT) == 0) {
		shs.shs_options |= HS_OPT_DRYRUN;
	}
	shs.shs_component_new = new_dev;
	shs.shs_start_blk = start_blk;
	shs.shs_has_label = ((label > 0) ? 1 : 0);
	shs.shs_number_blks = size;
	shs.shs_key_new = newnp->key;
	if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde, NULL) != 0) {
		if (options & MDCMD_DOIT) {
			(void) del_key_name(sp, newnp, ep);
		}
		return (mdstealerror(ep, &shs.mde));
	}

	/* clear cache */
	meta_invalidate_name(oldnp);
	meta_invalidate_name(newnp);
	meta_invalidate_hsp(hspnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Hotspare %s is replaced with %s\n"),
		    hspnp->hspname, oldnp->cname, newnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * enable hotspares
 */
int
meta_hs_enable(
	mdsetname_t	*sp,
	mdnamelist_t	*hsnlp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspnamelist_t	*hspnlp = NULL;
	mdhspnamelist_t	*hspnp;
	set_hs_params_t	shs;
	int		rval = -1;

	/* should have a set */
	assert(sp != NULL);

	/* setup device info */
	(void) memset(&shs, 0, sizeof (shs));
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);
	shs.shs_cmd = FIX_HOT_SPARE;
	shs.shs_options = HS_OPT_NONE;
	/* If DOIT is not set, it's a dryrun */
	if ((options & MDCMD_DOIT) == 0) {
		shs.shs_options |= HS_OPT_DRYRUN;
	}

	/* get the list of hotspare names */
	if (meta_get_hsp_names(sp, &hspnlp, 0, ep) < 0)
		goto out;

	/* enable hotspares for each components */
	for (; (hsnlp != NULL); hsnlp = hsnlp->next) {
		mdname_t	*hsnp = hsnlp->namep;
		md_dev64_t	fs_dev;
		int		rebind = 0;
		diskaddr_t	size, label, start_blk;

		/* get the file_system dev binding */
		if (meta_getdev(sp, hsnp, ep) != 0)
			return (-1);
		fs_dev = hsnp->dev;

		/*
		 * search for the component in each hotspare pool
		 * and replace it (instead of enable) if the binding
		 * has changed.
		 */
		for (hspnp = hspnlp; (hspnp != NULL); hspnp = hspnp->next) {
			/*
			 * in_hsp will call meta_get_hsp which will fill
			 * in hspnp with metadb version of component
			 */
			meta_invalidate_hsp(hspnp->hspnamep);
			if (in_hsp(sp, hspnp->hspnamep, hsnp, 0, -1, ep) != 0) {
				/*
				 * check for the case where the dev_t has
				 * changed between the filesystem and the
				 * metadb.  This is called a rebind, and
				 * is handled by meta_hs_replace.
				 */
				if (fs_dev != hsnp->dev) {
					/*
					 * establish file system binding
					 * with invalid start/end
					 */
					rebind++;
					hsnp->dev = fs_dev;
					hsnp->start_blk = -1;
					hsnp->end_blk = -1;
					rval = meta_hs_replace(sp,
					    hspnp->hspnamep,
					    hsnp, hsnp, options, ep);
					if (rval != 0)
						goto out;
				}
			}
		}
		if (rebind)
			continue;

		/* enable the component in all hotspares that use it */
		if (meta_check_hotspare(sp, hsnp, ep) != 0)
			goto out;

		if ((size = metagetsize(hsnp, ep)) == MD_DISKADDR_ERROR)
			goto out;
		if ((label = metagetlabel(hsnp, ep)) == MD_DISKADDR_ERROR)
			goto out;
		if ((start_blk = metagetstart(sp, hsnp, ep))
		    == MD_DISKADDR_ERROR)
			goto out;
		if (start_blk >= size) {
			(void) mdsyserror(ep, ENOSPC, hsnp->cname);
			goto out;
		}

		/* enable hotspare */
		shs.shs_component_old = hsnp->dev;
		shs.shs_component_new = hsnp->dev;
		shs.shs_start_blk = start_blk;
		shs.shs_has_label = ((label > 0) ? 1 : 0);
		shs.shs_number_blks = size;
		if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde, hsnp->cname) != 0) {
			rval = mdstealerror(ep, &shs.mde);
			goto out;
		}

		/*
		 * Are we dealing with a non-local set? If so need to update
		 * the local namespace so that the disk record has the correct
		 * devid.
		 */
		if (!metaislocalset(sp)) {
			rval = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET,
			    hsnp->cname, ep);

			if (rval != METADEVADM_SUCCESS) {
				/*
				 * Failed to update the local set. Nothing to
				 * do here apart from report the error. The
				 * namespace is most likely broken and some
				 * form of remedial recovery is going to
				 * be required.
				 */
				mde_perror(ep, "");
				mdclrerror(ep);
			}
		}

		/* clear cache */
		meta_invalidate_name(hsnp);

		/* let em know */
		if (options & MDCMD_PRINT) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "hotspare %s is enabled\n"),
			    hsnp->cname);
			(void) fflush(stdout);
		}
	}

	/* clear whole cache */
	for (hspnp = hspnlp; (hspnp != NULL); hspnp = hspnp->next) {
		meta_invalidate_hsp(hspnp->hspnamep);
	}


	/* return success */
	rval = 0;

out:
	if (hspnlp)
		metafreehspnamelist(hspnlp);
	return (rval);
}

/*
 * check for dups in the hsp itself
 */
static int
check_twice(
	md_hsp_t	*hspp,
	uint_t		hsi,
	md_error_t	*ep
)
{
	mdhspname_t	*hspnp = hspp->hspnamep;
	mdname_t	*thisnp;
	uint_t		h;

	thisnp = hspp->hotspares.hotspares_val[hsi].hsnamep;
	for (h = 0; (h < hsi); ++h) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[h];
		mdname_t	*hsnp = hsp->hsnamep;

		if (meta_check_overlap(hspnp->hspname, thisnp, 0, -1,
		    hsnp, 0, -1, ep) != 0)
			return (-1);
	}
	return (0);
}

/*
 * check hsp
 */
/*ARGSUSED2*/
int
meta_check_hsp(
	mdsetname_t	*sp,
	md_hsp_t	*hspp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspname_t	*hspnp = hspp->hspnamep;
	uint_t		hsi;

	/* check hotspares */
	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];
		mdname_t	*hsnp = hsp->hsnamep;
		diskaddr_t	size;

		/* check hotspare */
		if (meta_check_hotspare(sp, hsnp, ep) != 0)
			return (-1);
		if ((size = metagetsize(hsnp, ep)) == MD_DISKADDR_ERROR) {
			return (-1);
		} else if (size == 0) {
			return (mdsyserror(ep, ENOSPC, hspnp->hspname));
		}

		/* check this hsp too */
		if (check_twice(hspp, hsi, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * create hsp
 */
int
meta_create_hsp(
	mdsetname_t	*sp,
	md_hsp_t	*hspp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdhspname_t	*hspnp = hspp->hspnamep;
	mdnamelist_t	*hsnlp = NULL;
	uint_t		hsi;
	int		rval = -1;

	/* validate hsp */
	if (meta_check_hsp(sp, hspp, options, ep) != 0)
		return (-1);

	/* if we're not doing anything, return success */
	if (! (options & MDCMD_DOIT))
		return (0);

	/* create hsp */
	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];
		mdname_t	*hsnp = hsp->hsnamep;

		(void) metanamelist_append(&hsnlp, hsnp);
	}
	options |= MDCMD_INIT;
	rval = meta_hs_add(sp, hspnp, hsnlp, options, ep);

	/* cleanup, return success */
	metafreenamelist(hsnlp);
	return (rval);
}

/*
 * initialize hsp
 * NOTE: this functions is metainit(1m)'s command line parser!
 */
int
meta_init_hsp(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*uname = argv[0];
	mdhspname_t	*hspnp = NULL;
	md_hsp_t	*hspp = NULL;
	uint_t		hsi;
	int		rval = -1;


	/* get hsp name */
	assert(argc > 0);
	if (argc < 1)
		goto syntax;
	if ((hspnp = metahspname(spp, uname, ep)) == NULL)
		goto out;
	assert(*spp != NULL);
	uname = hspnp->hspname;

	if (!(options & MDCMD_NOLOCK)) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep))
			goto out;

		if (meta_check_ownership(*spp, ep) != 0)
			goto out;
	}

	/* see if it exists already */
	if (is_existing_metadevice(*spp, uname)) {
		mdname_t	*np;
		if ((np = metaname(spp, uname, META_DEVICE, ep)) != NULL)
			if ((meta_get_unit(*spp, np, ep)) != NULL)
				return (mderror(ep, MDE_NAME_IN_USE, uname));
	}

	if (meta_get_hsp(*spp, hspnp, ep) != NULL) {
		(void) mdhsperror(ep, MDE_HSP_ALREADY_SETUP,
		    hspnp->hsp, uname);
		goto out;
	} else if (! mdishsperror(ep, MDE_INVAL_HSP)) {
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

	/* allocate hsp */
	hspp = Zalloc(sizeof (*hspp));
	hspp->hotspares.hotspares_len = argc;
	if (argc > 0) {
		hspp->hotspares.hotspares_val =
		    Zalloc(argc * sizeof (*hspp->hotspares.hotspares_val));
	}

	/* setup pool */
	hspp->hspnamep = hspnp;

	/* parse hotspares */
	for (hsi = 0; ((argc > 0) && (hsi < hspp->hotspares.hotspares_len));
	    ++hsi) {
		md_hs_t		*hsp = &hspp->hotspares.hotspares_val[hsi];
		mdname_t	*hsnamep;

		/* parse hotspare name */
		if ((hsnamep = metaname(spp, argv[0],
		    LOGICAL_DEVICE, ep)) == NULL)
			goto out;
		hsp->hsnamep = hsnamep;
		--argc, ++argv;
	}

	/* we should be at the end */
	if (argc != 0)
		goto syntax;

	/* create hotspare pool */
	if (meta_create_hsp(*spp, hspp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */
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
	if (hspp != NULL)
		meta_free_hsp(hspp);
	return (rval);
}

/*
 * reset hotspare pool
 */
int
meta_hsp_reset(
	mdsetname_t	*sp,
	mdhspname_t	*hspnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_hsp_t	*hspp;
	set_hs_params_t	shs;
	uint_t		i;
	int		rval = -1;

	/* should have the same set */
	assert(sp != NULL);
	assert(hspnp == NULL || hspnp->hsp == MD_HSP_NONE ||
	    sp->setno == HSP_SET(hspnp->hsp));

	/* reset all hotspares */
	if (hspnp == NULL) {
		mdhspnamelist_t	*hspnlp = NULL;
		mdhspnamelist_t	*p;

		/* for each hotspare pool */
		rval = 0;
		if (meta_get_hsp_names(sp, &hspnlp, 0, ep) < 0)
			return (-1);
		for (p = hspnlp; (p != NULL); p = p->next) {
			/* reset hotspare pool */
			hspnp = p->hspnamep;

			/*
			 * If this is a multi-node set, we send a series
			 * of individual metaclear commands.
			 */
			if (meta_is_mn_set(sp, ep)) {
				if (meta_mn_send_metaclear_command(sp,
				    hspnp->hspname, options, 0, ep) != 0) {
					rval = -1;
					break;
				}
			} else {
				if (meta_hsp_reset(sp, hspnp, options,
				    ep) != 0) {
					rval = -1;
					break;
				}
			}
		}

		/* cleanup, return success */
		metafreehspnamelist(hspnlp);
		return (rval);
	}

	/* get unit structure */
	if ((hspp = meta_get_hsp(sp, hspnp, ep)) == NULL)
		return (-1);

	/* make sure nobody owns us */
	if (hspp->refcount > 0) {
		return (mdhsperror(ep, MDE_HSP_IN_USE, hspnp->hsp,
		    hspnp->hspname));
	}

	/* clear hotspare pool members */
	(void) memset(&shs, 0, sizeof (shs));
	MD_SETDRIVERNAME(&shs, MD_HOTSPARES, sp->setno);
	shs.shs_cmd = DELETE_HOT_SPARE;
	shs.shs_hot_spare_pool = hspnp->hsp;
	for (i = 0; (i < hspp->hotspares.hotspares_len); ++i) {
		md_hs_t		*hs = &hspp->hotspares.hotspares_val[i];
		mdname_t	*hsnamep = hs->hsnamep;

		/* clear cache */
		meta_invalidate_name(hsnamep);

		/* clear hotspare */
		shs.shs_component_old = hsnamep->dev;
		shs.shs_options = HS_OPT_FORCE;
		/* If DOIT is not set, it's a dryrun */
		if ((options & MDCMD_DOIT) == 0) {
			shs.shs_options |= HS_OPT_DRYRUN;
		}
		if (metaioctl(MD_IOCSET_HS, &shs, &shs.mde, NULL) != 0) {
			(void) mdstealerror(ep, &shs.mde);
			goto out;
		}
	}

	/* clear hotspare pool */
	if (meta_hsp_delete(sp, hspnp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Hotspare pool is cleared\n"),
		    hspnp->hspname);
		(void) fflush(stdout);
	}

	/* clear subdevices (nothing to do) */

	/* cleanup, return success */
out:
	meta_invalidate_hsp(hspnp);
	return (rval);
}
