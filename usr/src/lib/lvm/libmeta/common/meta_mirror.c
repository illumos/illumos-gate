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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
 * mirror operations
 */

#include <meta.h>
#include <sys/lvm/md_mirror.h>
#include <sys/lvm/md_convert.h>

#include <ctype.h>
#include <stddef.h>

/*
 * FUNCTION:    meta_get_mirror_names()
 * INPUT:       sp      - the set name to get mirrors from
 *              options - options from the command line
 * OUTPUT:      nlpp    - list of all mirror names
 *              ep      - return error pointer
 * RETURNS:     int     - -1 if error, 0 success
 * PURPOSE:     returns a list of all mirrors in the metadb
 *              for all devices in the specified set
 */
int
meta_get_mirror_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	return (meta_get_names(MD_MIRROR, sp, nlpp, options, ep));
}

/*
 * free mirror unit
 */
void
meta_free_mirror(
	md_mirror_t	*mirrorp
)
{
	Free(mirrorp);
}

/*
 * get mirror unit
 */
static md_mirror_t *
meta_get_mirror_common(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	int		fast,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = mirnp->drivenamep;
	char		*miscname;
	mm_unit_t	*mm;
	md_mirror_t	*mirrorp;
	uint_t		smi, nsm;
	md_resync_ioctl_t ri;

	/* must have set */
	assert(sp != NULL);

	/* short circuit */
	if (dnp->unitp != NULL) {
		assert(dnp->unitp->type == MD_METAMIRROR);
		return ((md_mirror_t *)dnp->unitp);
	}

	/* get miscname and unit */
	if ((miscname = metagetmiscname(mirnp, ep)) == NULL)
		return (NULL);
	if (strcmp(miscname, MD_MIRROR) != 0) {
		(void) mdmderror(ep, MDE_NOT_MM, meta_getminor(mirnp->dev),
		    mirnp->cname);
		return (NULL);
	}
	if ((mm = (mm_unit_t *)meta_get_mdunit(sp, mirnp, ep)) == NULL)
		return (NULL);
	assert(mm->c.un_type == MD_METAMIRROR);

	/* allocate mirror */
	mirrorp = Zalloc(sizeof (*mirrorp));

	/* get common info */
	mirrorp->common.namep = mirnp;
	mirrorp->common.type = mm->c.un_type;
	mirrorp->common.state = mm->c.un_status;
	mirrorp->common.capabilities = mm->c.un_capabilities;
	mirrorp->common.parent = mm->c.un_parent;
	mirrorp->common.size = mm->c.un_total_blocks;
	mirrorp->common.user_flags = mm->c.un_user_flags;
	mirrorp->common.revision = mm->c.un_revision;

	/* get options */
	mirrorp->read_option = mm->un_read_option;
	mirrorp->write_option = mm->un_write_option;
	mirrorp->pass_num = mm->un_pass_num;

	/* get submirrors */
	for (smi = 0, nsm = 0; (smi < NMIRROR); ++smi) {
		mm_submirror_t	*mmsp = &mm->un_sm[smi];
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];

		/* get submirror state */
		mdsp->state = mmsp->sm_state;
		if (mdsp->state == SMS_UNUSED)
			continue;
		++nsm;

		/* get submirror time of last state change */
		mdsp->timestamp = mmsp->sm_timestamp;

		/* get submirror flags */
		mdsp->flags = mmsp->sm_flags;

		/* get submirror name */
		mdsp->submirnamep = metakeyname(&sp, mmsp->sm_key, fast, ep);
		if (mdsp->submirnamep == NULL)
			goto out;
	}
	assert(nsm == mm->un_nsm);

	/* get resync info */
	(void) memset(&ri, 0, sizeof (ri));
	ri.ri_mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&ri, MD_MIRROR, sp->setno);
	if (metaioctl(MD_IOCGETSYNC, &ri, &ri.mde, mirnp->cname) != 0) {
		(void) mdstealerror(ep, &ri.mde);
		goto out;
	}
	mirrorp->percent_done = ri.ri_percent_done;
	mirrorp->percent_dirty = ri.ri_percent_dirty;

	/* cleanup, return success */
	Free(mm);
	dnp->unitp = (md_common_t *)mirrorp;
	return (mirrorp);

	/* cleanup, return error */
out:
	Free(mm);
	meta_free_mirror(mirrorp);
	return (NULL);
}

/*
 * get mirror unit
 */
md_mirror_t *
meta_get_mirror(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	md_error_t	*ep
)
{
	return (meta_get_mirror_common(sp, mirnp, 0, ep));
}

/*
 * check mirror for dev
 */
static int
in_mirror(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	md_mirror_t	*mirrorp;
	uint_t		smi;

	/* should be in the same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* get unit */
	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	/* look in submirrors */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		/* skip unused submirrors */
		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		/* check overlap */
		if (metaismeta(submirnp))
			continue;
		if (meta_check_overlap(mirnp->cname, np, slblk, nblks,
		    submirnp, 0, -1, ep) != 0)
			return (-1);
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a mirror
 */
int
meta_check_inmirror(
	mdsetname_t	*sp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdnamelist_t	*mirrornlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each mirror */
	if (meta_get_mirror_names(sp, &mirrornlp, 0, ep) < 0)
		return (-1);
	for (p = mirrornlp; (p != NULL); p = p->next) {
		mdname_t	*mirnp = p->namep;

		/* check mirror */
		if (in_mirror(sp, mirnp, np, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreenamelist(mirrornlp);
	return (rval);
}

/*
 * Check to see if the primary mirror is built on top of a
 * root slice which is mounted. This check is primarily to
 * account for this case -
 *
 * # metainit -f d1 1 1 <root slice>
 * # metainit d0 -m d1
 * # metainit d2 1 1 ctds
 * # metattach d0 d2
 *
 * The metattach here needs to fail if the root slice is
 * being mirrored; otherwise there is a potential for
 * data corruption.
 */
static int
meta_check_primary_mirror(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	md_error_t	*ep
)
{
	int		smi;
	char		*curroot;
	char		*temproot;
	mdname_t	*rootnp;
	md_mirror_t	*mirrorp;
	md_stripe_t	*stripep;
	md_row_t	*rp;
	md_comp_t	*cp;

	if ((curroot = meta_get_current_root(ep)) == NULL)
		return (-1);

	/*
	 * We need to take the canonical name here otherwise the call to
	 * metaname will add a bad entry to the drivelistp cache and
	 * things will get nasty later on.
	 * However we also need to trap the case where we have a logical
	 * device name and meta_canonicalize returns NULL.
	 */
	temproot = meta_canonicalize(sp, curroot);
	if (temproot != NULL) {
		curroot = Strdup(temproot);
		Free(temproot);
	}

	/*
	 * Get device name of current root metadevice. If root
	 * is net mounted as happens if we're part of the
	 * install process, rootnp will be set to NULL and we
	 * return success.
	 *
	 * Since curroot should be a complete path, we only
	 * need to check whether the device is a logical device.
	 * The metaname below returns NULL if curroot is not a logical
	 * device.
	 */
	if ((rootnp = metaname(&sp, curroot, LOGICAL_DEVICE, ep)) == NULL)
		return (0);
	/*
	 * If we're here, the curroot is a mounted on a logical device.
	 * Make sure this mirror is not on the root logical device.
	 */
	if (metaismeta(mirnp)) {
		if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
			return (-1);

		for (smi = 0; (smi < NMIRROR); ++smi) {
			/* Check all submirrors */
			md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
			mdname_t	*submirnamep = mdsp->submirnamep;

			/* skip unused submirrors */
			if (submirnamep == NULL) {
				assert(mdsp->state == SMS_UNUSED);
				continue;
			}
			/* check if submirror is a stripe or not */
			if (strcmp(metagetmiscname(submirnamep, ep), MD_STRIPE)
			    != 0)
				return (-1);
			if ((stripep = meta_get_stripe(sp, submirnamep, ep))
			    == NULL)
				return (-1);

			/*
			 * Examine the first component of the first row and
			 * check to see if it has a mounted root slice
			 */
			rp = &stripep->rows.rows_val[0];
			cp = &rp->comps.comps_val[0];
			/*
			 * we just care about the component built on
			 * top of a raw device
			 */
			if (!metaismeta(cp->compnamep)) {
				/*
				 * If root device is the 1st component of
				 * the stripe, then fail.
				 */
				if (strcmp(rootnp->cname, cp->compnamep->cname)
				    == 0) {
					(void) mduseerror(ep, MDE_IS_MOUNTED,
					rootnp->dev, "/", rootnp->cname);
					return (-1);
				}
			}
		}
	}
	/* return success */
	return (0);
}

/*
 * check submirror
 */
int
meta_check_submirror(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdname_t	*mirnp,
	int		force,
	md_error_t	*ep
)
{
	mdchkopts_t	options = 0;
	md_common_t	*mdp;

	/* make sure we have a metadevice disk */
	if (metachkmeta(np, ep) != 0)
		return (-1);

	/*
	 * Check to see if the primary mirror consists of a root
	 * mounted device
	 */
	if (mirnp && (!force) && ((meta_check_primary_mirror(sp, mirnp, ep)
	    != 0)))
		return (-1);

	/* check to ensure that it is not already in use */
	if ((! force) &&
	    (meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0)) {
		return (-1);
	}

	/* make sure it is in the set */
	if (meta_check_inset(sp, np, ep) != 0)
		return (-1);

	/* make sure its not in a metadevice */
	if (! metaismeta(np)) {		/* Non-metadevices */
		if (meta_check_inmeta(sp, np, options, 0, -1, ep) != 0)
			return (-1);
	} else {			/* Metadevices only! */
		/* make sure it can be parented */
		if ((mdp = meta_get_unit(sp, np, ep)) == NULL)
			return (-1);

		if ((! (mdp->capabilities & MD_CAN_PARENT)) ||
		    (! (mdp->capabilities & MD_CAN_SUB_MIRROR)) ||
		    (mdp->parent != MD_NO_PARENT)) {
			return (mdmderror(ep, MDE_INVAL_UNIT,
					meta_getminor(np->dev), np->cname));
		}
	}

	/* return success */
	return (0);
}

/*
 * convert read options
 */
char *
rd_opt_to_name(
	mm_rd_opt_t	opt
)
{
	switch (opt) {
	case RD_LOAD_BAL:
		return ("roundrobin");
	case RD_GEOMETRY:
		return ("geometric");
	case RD_FIRST:
		return ("first");
	default:
		assert(0);
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

static char *
rd_opt_to_opt(
	mm_rd_opt_t	opt
)
{
	switch (opt) {
	case RD_LOAD_BAL:
		return (NULL);	/* default */
	case RD_GEOMETRY:
		return ("-g");
	case RD_FIRST:
		return ("-r");
	default:
		assert(0);
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

int
name_to_rd_opt(
	char		*uname,
	char		*name,
	mm_rd_opt_t	*optp,
	md_error_t	*ep
)
{
	if (strcasecmp(name, "roundrobin") == 0) {
		*optp = RD_LOAD_BAL;
		return (0);
	}
	if (strcasecmp(name, "geometric") == 0) {
		*optp = RD_GEOMETRY;
		return (0);
	}
	if (strcasecmp(name, "first") == 0) {
		*optp = RD_FIRST;
		return (0);
	}
	return (meta_cook_syntax(ep, MDE_BAD_RD_OPT, uname, 1, &name));
}

/*
 * convert write options
 */
char *
wr_opt_to_name(
	mm_wr_opt_t	opt
)
{
	switch (opt) {
	case WR_PARALLEL:
		return ("parallel");
	case WR_SERIAL:
		return ("serial");
	default:
		assert(0);
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

static char *
wr_opt_to_opt(
	mm_wr_opt_t	opt
)
{
	switch (opt) {
	case WR_PARALLEL:
		return (NULL);	/* default */
	case WR_SERIAL:
		return ("-S");
	default:
		assert(0);
		return (dgettext(TEXT_DOMAIN, "invalid"));
	}
}

int
name_to_wr_opt(
	char		*uname,
	char		*name,
	mm_wr_opt_t	*optp,
	md_error_t	*ep
)
{
	if (strcasecmp(name, "parallel") == 0) {
		*optp = WR_PARALLEL;
		return (0);
	}
	if (strcasecmp(name, "serial") == 0) {
		*optp = WR_SERIAL;
		return (0);
	}
	return (meta_cook_syntax(ep, MDE_BAD_WR_OPT, uname, 1, &name));
}

/*
 * convert pass numbers
 */
int
name_to_pass_num(
	char		*uname,
	char		*name,
	mm_pass_num_t	*passp,
	md_error_t	*ep
)
{
	if ((sscanf(name, "%hd", passp) != 1) ||
	    (*passp < 0) || (*passp > MD_PASS_MAX)) {
		return (meta_cook_syntax(ep, MDE_BAD_PASS_NUM,
		    uname, 1, &name));
	}
	return (0);
}

/*
 * convert resync option
 */

static char *
resync_opt_to_name(
	uint_t	tstate
)
{
	if (tstate & MD_ABR_CAP)
		return (dgettext(TEXT_DOMAIN, "application based"));
	else
		return (dgettext(TEXT_DOMAIN, "optimized resync"));
}

/*
 * print mirror
 */
static int
mirror_print(
	md_mirror_t	*mirrorp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		smi;
	char		*p;
	int		rval = -1;


	if (options & PRINT_LARGEDEVICES) {
		if ((mirrorp->common.revision & MD_64BIT_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	if (options & PRINT_FN) {
		if ((mirrorp->common.revision & MD_FN_META_DEV) == 0) {
			rval = 0;
			goto out;
		}
	}

	/* print name and -m */
	if (fprintf(fp, "%s -m", mirrorp->common.namep->cname) == EOF)
		goto out;

	/* print submirrors */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep = mdsp->submirnamep;

		/* skip unused submirrors */
		if (submirnamep == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		/* print submirror */
		if (fprintf(fp, " %s", submirnamep->rname) == EOF)
			goto out;
	}

	/* print options */
	if ((p = rd_opt_to_opt(mirrorp->read_option)) != NULL) {
		if (fprintf(fp, " %s", p) == EOF)
			goto out;
	}
	if ((p = wr_opt_to_opt(mirrorp->write_option)) != NULL) {
		if (fprintf(fp, " %s", p) == EOF)
			goto out;
	}
	if (fprintf(fp, " %u\n", mirrorp->pass_num) == EOF)
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
 * convert submirror state to name
 */
char *
sm_state_to_name(
	md_submirror_t	*mdsp,
	md_status_t	mirror_status,
	md_timeval32_t	*tvp,
	uint_t		tstate
)
{
	static char	state_to_str[100];
	sm_state_t	state = mdsp->state;
	uint_t		is_target = mdsp->flags & MD_SM_RESYNC_TARGET;

	/* grab time */
	if (tvp != NULL)
		*tvp = mdsp->timestamp;

	/*
	 * Only return Unavailable if there is no flagged error on the
	 * submirror. If the mirror has received any writes since the submirror
	 * went into Unavailable state a resync is required. To alert the
	 * administrator to this we return a 'Needs maintenance' message.
	 */
	if ((tstate != 0) && (state & SMS_RUNNING)) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* all is well */
	if (state & SMS_RUNNING) {
		if (!(mirror_status & MD_UN_OPT_NOT_DONE) ||
		    ((mirror_status & MD_UN_OPT_NOT_DONE) && !is_target)) {
			return (dgettext(TEXT_DOMAIN, "Okay"));
		}
	}

	/* resyncing, needs repair */
	if ((state & (SMS_COMP_RESYNC | SMS_ATTACHED_RESYNC |
	    SMS_OFFLINE_RESYNC)) ||
	    (mirror_status & MD_UN_OPT_NOT_DONE)) {
		if (mirror_status & MD_UN_RESYNC_ACTIVE) {
			return (dgettext(TEXT_DOMAIN, "Resyncing"));
		}
		if (mirror_status & MD_UN_RESYNC_CANCEL) {
			return (dgettext(TEXT_DOMAIN, "Resync cancelled"));
		}
		return (dgettext(TEXT_DOMAIN, "Needs maintenance"));
	}

	/* needs repair */
	if (state & (SMS_COMP_ERRED | SMS_ATTACHED | SMS_OFFLINE)) {
		if (mirror_status & MD_UN_RESYNC_CANCEL) {
			return (dgettext(TEXT_DOMAIN, "Resync cancelled"));
		}
		return (dgettext(TEXT_DOMAIN, "Needs maintenance"));
	}

	/* unknown */
	assert(0);
	(void) sprintf(state_to_str, "0x%x", state);
	return (state_to_str);
}

/*
 * convert submirror state to repair action
 */
int
sm_state_to_action(
	mdsetname_t	*sp,
	md_submirror_t	*mdsp,
	md_status_t	mirror_status,
	md_mirror_t	*mirrorp,
	char		**actionp,
	md_error_t	*ep
)
{
	static char	buf[1024];
	mdname_t	*submirnamep = mdsp->submirnamep;
	sm_state_t	state = mdsp->state;
	char		*miscname;

	/* all is well */
	*actionp = NULL;
	if (mirror_status & MD_UN_RESYNC_ACTIVE)
		return (0);
	if ((state == SMS_RUNNING) && !(mirror_status & MD_UN_OPT_NOT_DONE))
		return (0);

	/* complete cancelled resync */
	if (mirror_status & MD_UN_RESYNC_CANCEL) {
		(void) snprintf(buf, sizeof (buf),
		    dgettext(TEXT_DOMAIN, "metasync %s"),
		    mirrorp->common.namep->cname);
		*actionp = buf;
		return (0);
	}

	/* replace stripe component */
	if ((metaismeta(submirnamep)) && (state & SMS_COMP_ERRED)) {
		if ((miscname = metagetmiscname(submirnamep, ep)) == NULL)
			return (-1);
		if (strcmp(miscname, MD_STRIPE) == 0) {
			mdname_t	*compnamep;
			comp_state_t	compstate;

			if (meta_find_erred_comp(sp, submirnamep,
			    &compnamep, &compstate, ep) != 0) {
				return (-1);
			}
			if (compstate != CS_LAST_ERRED)
				(void) snprintf(buf, sizeof (buf),
				    "metareplace %s %s <%s>",
				    mirrorp->common.namep->cname,
				    compnamep->cname,
				    dgettext(TEXT_DOMAIN, "new device"));
			else
				(void) snprintf(buf, sizeof (buf),
				    dgettext(TEXT_DOMAIN,
				    "after replacing \"Maintenance\" "
				    "components:\n"
				    "\t\tmetareplace %s %s <new device>"),
				    mirrorp->common.namep->cname,
				    compnamep->cname);
			*actionp = buf;
			return (0);
		}
	}

	/* resync mirror */
	if ((state & (SMS_ATTACHED_RESYNC | SMS_OFFLINE_RESYNC |
	    SMS_COMP_RESYNC | SMS_ATTACHED)) ||
	    (mirror_status & MD_UN_OPT_NOT_DONE)) {
		(void) snprintf(buf, sizeof (buf), "metasync %s",
		    mirrorp->common.namep->cname);
		*actionp = buf;
		return (0);
	}

	/* online submirror */
	if (state & SMS_OFFLINE) {
		(void) snprintf(buf, sizeof (buf), "metaonline %s %s",
		    mirrorp->common.namep->cname, submirnamep->cname);
		*actionp = buf;
		return (0);
	}

	/* unknown action */
	*actionp = dgettext(TEXT_DOMAIN, "???");
	return (0);
}

/*
 * print mirror options
 */
int
meta_print_mirror_options(
	mm_rd_opt_t	read_option,
	mm_wr_opt_t	write_option,
	mm_pass_num_t	pass_num,
	uint_t		tstate,
	char		*fname,
	mdsetname_t	*sp,
	FILE		*fp,
	md_error_t	*ep
)
{
	char		*p;
	int		rval = -1;

	/* print options */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Pass: %u\n"),
	    pass_num) == EOF) {
		goto out;
	}
	if ((p = rd_opt_to_opt(read_option)) == NULL)
		p = dgettext(TEXT_DOMAIN, "default");
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Read option: %s (%s)\n"),
	    rd_opt_to_name(read_option), p) == EOF) {
		goto out;
	}
	if ((p = wr_opt_to_opt(write_option)) == NULL)
		p = dgettext(TEXT_DOMAIN, "default");
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Write option: %s (%s)\n"),
	    wr_opt_to_name(write_option), p) == EOF) {
		goto out;
	}
	/* Display resync option for mirror, if MultiNode set */
	if (meta_is_mn_set(sp, ep)) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Resync option: %s\n"),
		    resync_opt_to_name(tstate)) == EOF) {
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

static char *
get_node_name(uint_t nid, md_error_t *ep)
{
	mndiskset_membershiplist_t	*nl, *p;
	int				n;
	char				*node_nm;

	/* get the known membership list */
	if (meta_read_nodelist(&n, &nl, ep)) {
		return (NULL);
	}

	/* find the matching node and return the name */
	for (p = nl; (p != NULL); p = p->next) {
		if (nid == p->msl_node_id) {
			/* match found */
			node_nm = Strdup(p->msl_node_name);
			goto out;
		}
	}

	/* match not found */
	node_nm = Strdup(dgettext(TEXT_DOMAIN, "None"));

out:
	meta_free_nodelist(nl);
	return (node_nm);
}

/*
 * report mirror
 */
static int
mirror_report(
	mdsetname_t	*sp,
	md_mirror_t	*mirrorp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_status_t	status = mirrorp->common.state;
	uint_t		smi;
	char		*p;
	int		rval = -1;
	uint_t		tstate = 0;

	/*
	 * check for the -B option. If -B and the metadevice is
	 * a 64 bit device, get the dev for relocation information
	 * printout. If not a 64 bit device, just don't print this
	 * information out but you need to go down to the subdevice
	 * level and print there if appropriate.
	 */
	if (options & PRINT_LARGEDEVICES) {
		if ((mirrorp->common.revision & MD_64BIT_META_DEV) == 0) {
			for (smi = 0; (smi < NMIRROR); ++smi) {
				md_submirror_t	*mdsp =
				    &mirrorp->submirrors[smi];
				mdname_t	*submirnamep =
				    mdsp->submirnamep;
				if (submirnamep == NULL) {
					continue;
				}
				if ((metaismeta(submirnamep)) &&
				    (meta_print_name(sp, submirnamep, nlpp,
				    fname, fp, options | PRINT_SUBDEVS, NULL,
				    ep) != 0)) {
					return (-1);
				}
			}
			rval = 0;
			goto out;
		} else {
			if (meta_getdevs(sp, mirrorp->common.namep,
			    nlpp, ep) != 0)
				goto out;
		}
	}

	/*
	 * check for the -D option. If -D and the name is
	 * a descriptive name, get the dev for relocation information
	 * printout. If not a descriptive name, don't print this
	 * information out but you need to go down to the subdevice
	 * level and print there if appropriate.
	 */
	if (options & PRINT_FN) {
		if ((mirrorp->common.revision & MD_FN_META_DEV) == 0) {
			for (smi = 0; (smi < NMIRROR); ++smi) {
				md_submirror_t	*mdsp =
				    &mirrorp->submirrors[smi];
				mdname_t	*submirnamep =
				    mdsp->submirnamep;
				if (submirnamep == NULL) {
					continue;
				}
				if ((metaismeta(submirnamep)) &&
				    (meta_print_name(sp, submirnamep, nlpp,
				    fname, fp, options | PRINT_SUBDEVS, NULL,
				    ep) != 0)) {
					return (-1);
				}
			}
			rval = 0;
			goto out;
		} else {
			if (meta_getdevs(sp, mirrorp->common.namep,
			    nlpp, ep) != 0)
				goto out;
		}
	}

	/* print header */
	if (options & PRINT_HEADER) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: Mirror\n"),
		    mirrorp->common.namep->cname) == EOF) {
			goto out;
		}
	}

	/* print submirrors, adjust status */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep = mdsp->submirnamep;
		char		*sm_state;
		md_timeval32_t	tv;
		char		*timep;

		/* skip unused submirrors */
		if (submirnamep == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		if (mdsp->state & SMS_OFFLINE)
			status &= ~MD_UN_OPT_NOT_DONE;

		/* print submirror */
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Submirror %u: %s\n"),
		    smi, submirnamep->cname) == EOF) {
			goto out;
		}

		/* print state */
		if (metaismeta(mdsp->submirnamep)) {
			if (meta_get_tstate(mdsp->submirnamep->dev, &tstate,
			    ep) != 0)
				return (-1);
		}
		sm_state = sm_state_to_name(mdsp, status, &tv,
		    tstate & MD_DEV_ERRORED);
		if (options & PRINT_TIMES) {
			timep = meta_print_time(&tv);
		} else {
			timep = "";
		}
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "      State: %-12s %s\n"),
		    sm_state, timep) == EOF) {
			goto out;
		}
	}

	/* print resync status */
	if (status & MD_UN_RESYNC_CANCEL) {
		/* Resync was cancelled but is restartable */
		if (mirrorp->common.revision & MD_64BIT_META_DEV) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync cancelled: %2d.%1d %% done\n"),
			    mirrorp->percent_done/10,
			    mirrorp->percent_done%10) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync cancelled: %d %% done\n"),
			    mirrorp->percent_done) == EOF) {
				goto out;
			}
		}
	} else if (status & MD_UN_RESYNC_ACTIVE) {
		if (mirrorp->common.revision & MD_64BIT_META_DEV) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync in progress: %2d.%1d %% done\n"),
			    mirrorp->percent_done/10,
			    mirrorp->percent_done%10) == EOF) {
				goto out;
			}
		} else {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync in progress: %d %% done\n"),
			    mirrorp->percent_done) == EOF) {
				goto out;
			}
		}
	}

	/* print options */
	if (meta_get_tstate(mirrorp->common.namep->dev, &tstate, ep) != 0)
		return (-1);

	if (meta_print_mirror_options(mirrorp->read_option,
	    mirrorp->write_option, mirrorp->pass_num,
	    tstate, fname, sp, fp, ep) != 0)
		return (-1);

	/* print mirror owner for multi-node metadevice */
	if (meta_is_mn_set(sp, ep)) {
		md_set_mmown_params_t	ownpar;
		mdname_t		*mirnp = mirrorp->common.namep;
		char			*node_name;

		(void) memset(&ownpar, 0, sizeof (ownpar));
		ownpar.d.mnum = meta_getminor(mirnp->dev);
		MD_SETDRIVERNAME(&ownpar, MD_MIRROR, sp->setno);

		if (metaioctl(MD_MN_GET_MM_OWNER, &ownpar, ep,
		    "MD_MN_GET_MM_OWNER") != 0) {
			return (-1);
		}

		node_name = get_node_name(ownpar.d.owner, ep);
		if (node_name == NULL)
			return (-1);
		else if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Owner: %s\n"),
		    node_name) == EOF) {
			Free(node_name);
			goto out;
		}
		Free(node_name);

	}

	/* print size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %lld blocks (%s)\n"),
	    mirrorp->common.size,
	    meta_number_to_string(mirrorp->common.size, DEV_BSIZE))
	    == EOF) {
		goto out;
	}

	/* MD_DEBUG stuff */
	if (options & PRINT_DEBUG) {
		mdname_t	*mirnp = mirrorp->common.namep;
		mm_unit_t	*mm;
		mddb_optloc_t	optloc;
		uint_t		i;

		/* get real mirror unit */
		if ((mm = (mm_unit_t *)meta_get_mdunit(sp, mirnp, ep))
		    == NULL) {
			return (-1);
		}
		assert(mm->c.un_type == MD_METAMIRROR);

		/* print dirty regions */
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
"    Regions which are dirty: %d%% (blksize %d num %d)\n"),
		    mirrorp->percent_dirty, mm->un_rrd_blksize,
		    mm->un_rrd_num) == EOF) {
			Free(mm);
			goto out;
		}

		/* print optimized resync record locations */
		(void) memset(&optloc, 0, sizeof (optloc));
		optloc.recid = mm->un_rr_dirty_recid;
		if (metaioctl(MD_DB_GETOPTLOC, &optloc, ep,
		    "MD_DB_GETOPTLOC") != 0) {
			Free(mm);
			return (-1);
		}
		for (i = 0; (i < ((sizeof optloc.li) / sizeof (optloc.li[0])));
		    ++i) {
			mddb_config_t	dbconf;
			char		*devname;

			(void) memset(&dbconf, 0, sizeof (dbconf));
			dbconf.c_id = optloc.li[i];
			dbconf.c_setno = sp->setno;
			dbconf.c_subcmd = MDDB_CONFIG_ABS;
			/* Don't need device id information from this ioctl */
			dbconf.c_locator.l_devid = (uint64_t)0;
			dbconf.c_locator.l_devid_flags = 0;
			if (metaioctl(MD_DB_ENDDEV, &dbconf, &dbconf.c_mde,
			    "MD_DB_ENDDEV") != 0) {
				Free(mm);
				return (mdstealerror(ep, &dbconf.c_mde));
			}
			if ((devname = splicename(&dbconf.c_devname))
			    == NULL) {
				devname = Strdup(dgettext(TEXT_DOMAIN,
				    "unknown"));
			}
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Resync record[%u]: %d (%s %d %d)\n"), i,
			    optloc.li[i], devname, dbconf.c_locator.l_blkno,
			    (dbconf.c_dbend - dbconf.c_locator.l_blkno + 1))
			    == EOF) {
				Free(mm);
				Free(devname);
				goto out;
			}
			Free(devname);
		}
		Free(mm);
	}

	/* print submirror details */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep = mdsp->submirnamep;
		char		*sm_state;
		md_timeval32_t	tv;
		char		*timep;
		md_stripe_t	*stripep;

		/* skip unused submirrors */
		if (submirnamep == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		if (options & PRINT_FN) {
			/* get unit structure */
			if ((stripep = meta_get_stripe_common(sp, submirnamep,
			    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
				goto out;

			if ((stripep->common.revision & MD_FN_META_DEV)
			    == 0)
				continue;
		}

		/* add extra line */
		if (fprintf(fp, "\n") == EOF)
			goto out;

		/* print submirror */
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "%s: Submirror of %s\n"),
		    submirnamep->cname,
		    mirrorp->common.namep->cname) == EOF) {
			goto out;
		}

		/* print state */
		if (metaismeta(mdsp->submirnamep)) {
			if (meta_get_tstate(mdsp->submirnamep->dev, &tstate, ep)
			    != 0)
				return (-1);
		}
		sm_state = sm_state_to_name(mdsp, status, &tv, NULL);
		if (options & PRINT_TIMES) {
			timep = meta_print_time(&tv);
		} else {
			timep = "";
		}

		if ((tstate & MD_DEV_ERRORED) == 0) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    State: %-12s %s\n"),
			    sm_state, timep) == EOF) {
				goto out;
			}

			/* print what to do */
			if (sm_state_to_action(sp, mdsp, status,
			    mirrorp, &p, ep) != 0)
				return (-1);
			if ((p != NULL) &&
			    (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Invoke: %s\n"), p) == EOF)) {
				goto out;
			}
		}

		/* print underlying metadevice */
		if ((metaismeta(submirnamep)) &&
		    (meta_print_name(sp, submirnamep, nlpp, fname, fp,
		    ((options & ~PRINT_HEADER) | PRINT_SUBDEVS),
		    NULL, ep) != 0)) {
			return (-1);
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
 * print/report mirror
 */
int
meta_mirror_print(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_mirror_t	*mirrorp;
	uint_t		smi;

	/* should have same set */
	assert(sp != NULL);
	assert((mirnp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev))));

	/* print all mirrors */
	if (mirnp == NULL) {
		mdnamelist_t	*nlp = NULL;
		mdnamelist_t	*p;
		int		cnt;
		int		rval = 0;

		/* get list */
		if ((cnt = meta_get_mirror_names(sp, &nlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recurse */
		for (p = nlp; (p != NULL); p = p->next) {
			mdname_t	*np = p->namep;

			if (meta_mirror_print(sp, np, nlpp, fname, fp,
			    options, ep) != 0)
				rval = -1;
		}

		/* cleanup, return success */
		metafreenamelist(nlp);
		return (rval);
	}

	/* get unit structure */
	if ((mirrorp = meta_get_mirror_common(sp, mirnp,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* check for parented */
	if ((! (options & PRINT_SUBDEVS)) &&
	    (MD_HAS_PARENT(mirrorp->common.parent))) {
		return (0);
	}

	/* print appropriate detail */
	if (options & PRINT_SHORT) {
		/* print mirror */
		if (mirror_print(mirrorp, fname, fp, options, ep) != 0)
			return (-1);

		/* print underlying metadevices */
		for (smi = 0; (smi < NMIRROR); ++smi) {
			md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
			mdname_t	*submirnamep = mdsp->submirnamep;

			/* skip unused submirrors */
			if (submirnamep == NULL) {
				assert(mdsp->state == SMS_UNUSED);
				continue;
			}

			/* print submirror */
			if (metaismeta(submirnamep)) {
				if (meta_print_name(sp, submirnamep, nlpp,
				    fname, fp, (options | PRINT_SUBDEVS), NULL,
				    ep) != 0) {
					return (-1);
				}
			}
		}

		/* return success */
		return (0);
	} else {
		return (mirror_report(sp, mirrorp, nlpp, fname, fp,
		    options, ep));
	}
}

/*
 * online submirror
 */
int
meta_mirror_online(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdname_t	*submirnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_i_off_on_t	mio;
	md_mirror_t	*mirrorp;
	md_set_desc	*sd;
	uint_t		tstate;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	/* Only valid for mirror without ABR set */
	if (meta_get_tstate(mirrorp->common.namep->dev, &tstate, ep) != 0)
		return (-1);
	if (tstate & MD_ABR_CAP) {
		(void) mderror(ep, MDE_ABR_SET, NULL);
		return (-1);
	}

	/*
	 * In a MN set, the master always executes the online command first.
	 * Before the master executes the IOC_ONLINE ioctl,
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_ONLINE ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the online command, each slave will
	 * call the IOC_ONLINE ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if ((MD_MNSET_DESC(sd)) && sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	/* online submirror */
	(void) memset(&mio, 0, sizeof (mio));
	mio.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&mio, MD_MIRROR, sp->setno);
	mio.submirror = submirnp->dev;
	if (metaioctl(MD_IOCONLINE, &mio, &mio.mde, NULL) != 0)
		return (mdstealerror(ep, &mio.mde));

	/* clear cache */
	meta_invalidate_name(mirnp);
	meta_invalidate_name(submirnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: submirror %s is onlined\n"),
		    mirnp->cname, submirnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * offline submirror
 */
int
meta_mirror_offline(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdname_t	*submirnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	int		force = ((options & MDCMD_FORCE) ? 1 : 0);
	md_i_off_on_t	mio;
	md_mirror_t	*mirrorp;
	md_set_desc	*sd;
	uint_t		tstate;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	/* Only valid for mirror without ABR set */
	if (meta_get_tstate(mirrorp->common.namep->dev, &tstate, ep) != 0)
		return (-1);
	if (tstate & MD_ABR_CAP) {
		(void) mderror(ep, MDE_ABR_SET, NULL);
		return (-1);
	}

	/*
	 * In a MN set, the master always executes the offline command first.
	 * Before the master executes the IOC_OFFLINE ioctl,
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_OFFLINE ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the offline command, each slave will
	 * call the IOC_OFFLINE ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if ((MD_MNSET_DESC(sd)) && sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	/* offline submirror */
	(void) memset(&mio, 0, sizeof (mio));
	mio.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&mio, MD_MIRROR, sp->setno);
	mio.submirror = submirnp->dev;
	mio.force_offline = force;
	if (metaioctl(MD_IOCOFFLINE, &mio, &mio.mde, NULL) != 0)
		return (mdstealerror(ep, &mio.mde));

	/* clear cache */
	meta_invalidate_name(mirnp);
	meta_invalidate_name(submirnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: submirror %s is offlined\n"),
		    mirnp->cname, submirnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * attach submirror to mirror
 * we actually never have to worry about crossing a thresh hold here.
 * 2 cases 1) attach and the only way the mirror can be 64 bit is if
 * one of the submirrors already is. 2) grow and the only way the mirror
 * is 64 bit is if one of the submirror's already is.
 */
int
meta_mirror_attach(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdname_t	*submirnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_att_struct_t	att;
	md_set_desc		*sd;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* just grow */
	if (submirnp == NULL) {
		return (meta_concat_generic(sp, mirnp, NULL, ep));
	}

	/* check submirror */
	if (meta_check_submirror(sp, submirnp, mirnp, 0, ep) != 0)
		return (-1);

	/* In dryrun mode (DOIT not set) we must not alter the mddb */
	if (options & MDCMD_DOIT) {
		/* store name in namespace */
		if (add_key_name(sp, submirnp, NULL, ep) != 0)
			return (-1);
	}

	/*
	 * In a MN set, the master always executes the attach command first.
	 * Before the master executes the IOC_ATTACH ioctl, in non-DRYRUN mode
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_ATTACH ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the attach command, each slave will
	 * call the IOC_ATTACH ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if ((MD_MNSET_DESC(sd)) && (options & MDCMD_DOIT) &&
		    sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	/* attach submirror */
	(void) memset(&att, 0, sizeof (att));
	att.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&att, MD_MIRROR, sp->setno);
	att.submirror = submirnp->dev;
	att.key = submirnp->key;
	/* if the comamnd was issued with -n option, use dryrun mode */
	if ((options & MDCMD_DOIT) == 0) {
		att.options = MDIOCTL_DRYRUN;
	}
	if (metaioctl(MD_IOCATTACH, &att, &att.mde, NULL) != 0) {
		/* In dryrun mode (DOIT not set) we must not alter the mddb */
		if (options & MDCMD_DOIT) {
			(void) del_key_name(sp, submirnp, ep);
		}
		return (mdstealerror(ep, &att.mde));
	}

	/* In dryrun mode (DOIT not set) we must not alter the mddb */
	if (options & MDCMD_DOIT) {
		/* clear cache */
		meta_invalidate_name(mirnp);
		meta_invalidate_name(submirnp);
	}

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: submirror %s %s\n"), mirnp->cname, submirnp->cname,
		    (options & MDCMD_DOIT) ? "is attached" : "would attach");
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * detach submirror
 */
int
meta_mirror_detach(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	mdname_t		*submirnp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	int			force = ((options & MDCMD_FORCE) ? 1 : 0);
	md_detach_params_t	detach;
	md_set_desc		*sd;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/*
	 * In a MN set, the master always executes the detach command first.
	 * Before the master executes the IOC_DETACH ioctl,
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_DETACH ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the detach command, each slave will
	 * call the IOC_DETACH ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if ((MD_MNSET_DESC(sd)) && sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	/* detach submirror */
	(void) memset(&detach, 0, sizeof (detach));
	detach.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&detach, MD_MIRROR, sp->setno);
	detach.submirror = submirnp->dev;
	detach.force_detach = force;
	if (metaioctl(MD_IOCDETACH, &detach, &detach.mde, NULL) != 0)
		return (mdstealerror(ep, &detach.mde));

	/* clear cache */
	meta_invalidate_name(mirnp);
	meta_invalidate_name(submirnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: submirror %s is detached\n"),
		    mirnp->cname, submirnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * get mirror parameters
 */
int
meta_mirror_get_params(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mm_params_t	*paramsp,
	md_error_t	*ep
)
{
	md_mirror_t	*mirrorp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* get unit */
	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	/* return parameters */
	(void) memset(paramsp, 0, sizeof (*paramsp));
	paramsp->read_option = mirrorp->read_option;
	paramsp->write_option = mirrorp->write_option;
	paramsp->pass_num = mirrorp->pass_num;
	return (0);
}

/*
 * set mirror parameters
 */
int
meta_mirror_set_params(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	mm_params_t		*paramsp,
	md_error_t		*ep
)
{
	md_mirror_params_t	mmp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* set parameters */
	(void) memset(&mmp, 0, sizeof (mmp));
	MD_SETDRIVERNAME(&mmp, MD_MIRROR, sp->setno);
	mmp.mnum = meta_getminor(mirnp->dev);
	mmp.params = *paramsp;
	if (metaioctl(MD_IOCCHANGE, &mmp, &mmp.mde, mirnp->cname) != 0)
		return (mdstealerror(ep, &mmp.mde));

	/* clear cache */
	meta_invalidate_name(mirnp);

	/* return success */
	return (0);
}

/*
 * invalidate submirror names
 */
static int
invalidate_submirrors(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	md_error_t	*ep
)
{
	md_mirror_t	*mirrorp;
	uint_t		smi;

	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}
		meta_invalidate_name(submirnp);
	}
	return (0);
}

/*
 * replace mirror component
 */
int
meta_mirror_replace(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	mdname_t		*oldnp,
	mdname_t		*newnp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	md_mirror_t		*mirrorp;
	uint_t			smi;
	replace_params_t	params;
	diskaddr_t		size, label, start_blk;
	md_dev64_t		old_dev, new_dev;
	diskaddr_t		new_start_blk, new_end_blk;
	int			rebind;
	md_set_desc		*sd;
	char			*new_devidp = NULL;
	int			ret;
	md_error_t		xep = mdnullerror;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* save new binding incase this is a rebind where oldnp==newnp */
	new_dev = newnp->dev;
	new_start_blk = newnp->start_blk;
	new_end_blk = newnp->end_blk;

	/* invalidate, then get the mirror (fill in oldnp from metadb) */
	meta_invalidate_name(mirnp);
	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		if (! metaismeta(submirnp))
			continue;

		meta_invalidate_name(submirnp);
		if (meta_get_unit(sp, submirnp, ep) == NULL)
			return (-1);
	}

	/* the old device binding is now established */
	if ((old_dev = oldnp->dev) == NODEV64)
		return (mdsyserror(ep, ENODEV, oldnp->cname));

	/*
	 * check for the case where oldnp and newnp indicate the same
	 * device, but the dev_t of the device has changed between old
	 * and new.  This is called a rebind.  On entry the dev_t
	 * represents the new device binding determined from the
	 * filesystem (meta_getdev). After calling meta_get_unit
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
	 * is that if we are rebinding then the call to meta_check_component()
	 * will cause the devid of the disk to be overwritten with what is in
	 * the replica namespace. The function that actually overwrites the
	 * devid is dr2drivedesc().
	 */
	if (newnp->drivenamep->devid != NULL)
		new_devidp = Strdup(newnp->drivenamep->devid);

	/* if it's a multi-node diskset clear new_devidp */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if (MD_MNSET_DESC(sd))
			new_devidp = NULL;
	}

	/* check it out (dup on rebind is ok) */
	if (meta_check_component(sp, newnp, 0, ep) != 0) {
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
		newnp->drivenamep->devid = Strdup(new_devidp);
		Free(new_devidp);
	}

	/* store name in namespace, allocate new key */
	if (add_key_name(sp, newnp, NULL, ep) != 0)
		return (-1);

	/*
	 * In a MN set, the master always executes the replace command first.
	 * Before the master executes the IOC_REPLACE ioctl, in non-DRYRUN mode
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_REPLACE ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the replace command, each slave will
	 * call the IOC_REPLACE ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((MD_MNSET_DESC(sd)) && (options & MDCMD_DOIT) &&
		    sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	if (rebind && !metaislocalset(sp)) {
		/*
		 * We are 'rebind'ing a disk that is in a diskset so as well
		 * as updating the diskset's namespace the local set needs
		 * to be updated because it also contains a reference to
		 * the disk in question.
		 */
		ret = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET,
		    newnp->cname, ep);

		if (ret != METADEVADM_SUCCESS) {
			(void) del_key_name(sp, newnp, &xep);
			return (-1);
		}
	}

	/* replace component */
	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&params, MD_MIRROR, sp->setno);
	params.cmd = REPLACE_COMP;
	params.old_dev = old_dev;
	params.new_dev = new_dev;
	params.start_blk = start_blk;
	params.has_label = ((label > 0) ? 1 : 0);
	params.number_blks = size;
	params.new_key = newnp->key;
	/* Is this just a dryrun ? */
	if ((options & MDCMD_DOIT) == 0) {
		params.options |= MDIOCTL_DRYRUN;
	}
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0) {
		(void) del_key_name(sp, newnp, ep);
		return (mdstealerror(ep, &params.mde));
	}

	/* clear cache */
	meta_invalidate_name(oldnp);
	meta_invalidate_name(newnp);
	if (invalidate_submirrors(sp, mirnp, ep) != 0) {
		meta_invalidate_name(mirnp);
		return (-1);
	}
	meta_invalidate_name(mirnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is replaced with %s\n"),
		    mirnp->cname, oldnp->cname, newnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * enable mirror component
 */
int
meta_mirror_enable(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	mdname_t		*compnp,
	mdcmdopts_t		options,
	md_error_t		*ep
)
{
	md_mirror_t		*mirrorp;
	uint_t			smi;
	replace_params_t	params;
	diskaddr_t		size, label, start_blk;
	md_dev64_t		fs_dev;
	md_set_desc		*sd;
	int			ret;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* get the file_system dev binding */
	if (meta_getdev(sp, compnp, ep) != 0)
		return (-1);
	fs_dev = compnp->dev;

	/* get the mirror unit (fill in compnp->dev with metadb version) */
	meta_invalidate_name(mirnp);
	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		if (! metaismeta(submirnp))
			continue;

		meta_invalidate_name(submirnp);
		if (meta_get_unit(sp, submirnp, ep) == NULL)
			return (-1);
	}

	/* the metadb device binding is now established */
	if (compnp->dev == NODEV64)
		return (mdsyserror(ep, ENODEV, compnp->cname));

	/*
	 * check for the case where the dev_t has changed between the
	 * filesystem and the metadb.  This is called a rebind, and
	 * is handled by meta_mirror_replace.
	 */
	if (fs_dev != compnp->dev) {
		/* establish file system binding with invalid start/end */
		compnp->dev = fs_dev;
		compnp->start_blk = -1;
		compnp->end_blk = -1;
		return (meta_mirror_replace(sp, mirnp,
		    compnp, compnp, options, ep));
	}

	/* setup mirror info */
	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(mirnp->dev);
	MD_SETDRIVERNAME(&params, MD_MIRROR, sp->setno);
	params.cmd = ENABLE_COMP;

	/* check it out */
	if (meta_check_component(sp, compnp, 0, ep) != 0) {
		if (! mdisuseerror(ep, MDE_ALREADY))
			return (-1);
		mdclrerror(ep);
	}

	if ((size = metagetsize(compnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((label = metagetlabel(compnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if ((start_blk = metagetstart(sp, compnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);
	if (start_blk >= size) {
		(void) mdsyserror(ep, ENOSPC, compnp->cname);
		return (-1);
	}

	/*
	 * In a MN set, the master always executes the replace command first.
	 * Before the master executes the IOC_REPLACE ioctl, in non-DRYRUN mode
	 * the master sends a message to all nodes to suspend writes to
	 * this mirror.  Then the master executes the IOC_REPLACE ioctl
	 * which resumes writes to this mirror from the master node.
	 * As each slave executes the replace command, each slave will
	 * call the IOC_REPLACE ioctl which will resume writes to this mirror
	 * from that slave node.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if ((MD_MNSET_DESC(sd)) && (options & MDCMD_DOIT) &&
		    sd->sd_mn_am_i_master)
			if (meta_mn_send_suspend_writes(
			    meta_getminor(mirnp->dev), ep) != 0)
				return (-1);
	}

	/* enable component */
	params.old_dev = compnp->dev;
	params.new_dev = compnp->dev;
	params.start_blk = start_blk;
	params.has_label = ((label > 0) ? 1 : 0);
	params.number_blks = size;

	/* Is this just a dryrun ? */
	if ((options & MDCMD_DOIT) == 0) {
		params.options |= MDIOCTL_DRYRUN;
	}
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0)
		return (mdstealerror(ep, &params.mde));

	/*
	 * Are we dealing with a non-local set? If so need to update the
	 * local namespace so that the disk record has the correct devid.
	 */
	if (!metaislocalset(sp)) {
		ret = meta_fixdevid(sp, DEV_UPDATE|DEV_LOCAL_SET, compnp->cname,
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
	meta_invalidate_name(compnp);
	if (invalidate_submirrors(sp, mirnp, ep) != 0) {
		meta_invalidate_name(mirnp);
		return (-1);
	}
	meta_invalidate_name(mirnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is enabled\n"),
		    mirnp->cname, compnp->cname);
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * check for dups in the mirror itself
 */
static int
check_twice(
	md_mirror_t	*mirrorp,
	uint_t		smi,
	md_error_t	*ep
)
{
	mdname_t	*mirnp = mirrorp->common.namep;
	mdname_t	*thisnp;
	uint_t		s;

	thisnp = mirrorp->submirrors[smi].submirnamep;
	for (s = 0; (s < smi); ++s) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[s];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL)
			continue;

		if (meta_check_overlap(mirnp->cname, thisnp, 0, -1,
		    submirnp, 0, -1, ep) != 0) {
			return (-1);
		}
	}
	return (0);
}

/*
 * check mirror
 */
int
meta_check_mirror(
	mdsetname_t	*sp,
	md_mirror_t	*mirrorp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*mirnp = mirrorp->common.namep;
	int		force = ((options & MDCMD_FORCE) ? 1 : 0);
	int		doit = ((options & MDCMD_DOIT) ? 1 : 0);
	uint_t		nsm = 0;
	uint_t		smi;

	/* check submirrors */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL)
			continue;
		++nsm;
	}
	if (nsm < 1) {
		return (mdmderror(ep, MDE_BAD_MIRROR,
		    meta_getminor(mirnp->dev), mirnp->cname));
	}
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;
		diskaddr_t	size;

		/* skip unused submirrors */
		if (submirnp == NULL) {
			if (mdsp->state != SMS_UNUSED) {
				return (mdmderror(ep, MDE_BAD_MIRROR,
				    meta_getminor(mirnp->dev), mirnp->cname));
			}
			continue;
		}

		/* check submirror */
		if (doit) {
			if (meta_check_submirror(sp, submirnp, NULL, force,
			    ep) != 0)
				return (-1);
			if ((size = metagetsize(submirnp, ep)) ==
			    MD_DISKADDR_ERROR) {
				return (-1);
			} else if (size == 0) {
				return (mdsyserror(ep, ENOSPC,
					submirnp->cname));
			}
		}

		/* check this mirror too */
		if (check_twice(mirrorp, smi, ep) != 0)
			return (-1);
	}

	/* check read option */
	switch (mirrorp->read_option) {
	case RD_LOAD_BAL:
	case RD_GEOMETRY:
	case RD_FIRST:
		break;
	default:
		return (mderror(ep, MDE_BAD_RD_OPT, mirnp->cname));
	}

	/* check write option */
	switch (mirrorp->write_option) {
	case WR_PARALLEL:
	case WR_SERIAL:
		break;
	default:
		return (mderror(ep, MDE_BAD_WR_OPT, mirnp->cname));
	}

	/* check pass number */
	if ((mirrorp->pass_num < 0) || (mirrorp->pass_num > MD_PASS_MAX))
		return (mderror(ep, MDE_BAD_PASS_NUM, mirnp->cname));

	/* return success */
	return (0);
}

/*
 * setup mirror geometry
 */
static int
mirror_geom(
	md_mirror_t	*mirrorp,
	mm_unit_t	*mm,
	md_error_t	*ep
)
{
	uint_t		write_reinstruct = 0;
	uint_t		read_reinstruct = 0;
	uint_t		round_cyl = 1;
	mdname_t	*smnp = NULL;
	uint_t		smi;
	mdgeom_t	*geomp;

	/* get worst reinstructs */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		if (submirnp == NULL)
			continue;

		if ((geomp = metagetgeom(submirnp, ep)) == NULL)
			return (-1);
		if (geomp->write_reinstruct > write_reinstruct)
			write_reinstruct = geomp->write_reinstruct;
		if (geomp->read_reinstruct > read_reinstruct)
			read_reinstruct = geomp->read_reinstruct;

		if (smnp == NULL)
			smnp = submirnp;
	}

	/* setup geometry from first submirror */
	assert(smnp != NULL);
	if ((geomp = metagetgeom(smnp, ep)) == NULL)
		return (-1);
	if (meta_setup_geom((md_unit_t *)mm, mirrorp->common.namep, geomp,
	    write_reinstruct, read_reinstruct, round_cyl, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * create mirror
 */
int
meta_create_mirror(
	mdsetname_t	*sp,
	md_mirror_t	*mirrorp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*mirnp = mirrorp->common.namep;
	mm_unit_t	*mm;
	diskaddr_t	submir_size = MD_DISKADDR_ERROR;
	ushort_t	nsm = 0;
	uint_t		smi;
	mdnamelist_t	*keynlp = NULL;
	md_set_params_t	set_params;
	int		rval = -1;
	md_timeval32_t	creation_time;
	int		create_flag = MD_CRO_32BIT;

	/* validate mirror */
	if (meta_check_mirror(sp, mirrorp, options, ep) != 0)
		return (-1);


	/* allocate mirror unit */
	mm = Zalloc(sizeof (*mm));

	if (meta_gettimeofday(&creation_time) == -1)
		return (mdsyserror(ep, errno, NULL));

	/* do submirrors */
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;
		mm_submirror_t	*mmsp = &mm->un_sm[smi];
		diskaddr_t	size;

		/* skip unused submirrors */
		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}
		++nsm;

		/* get size */
		if ((size = metagetsize(submirnp, ep)) == MD_DISKADDR_ERROR)
			goto out;
		assert(size > 0);

		/* adjust for smallest submirror */
		if (submir_size == MD_DISKADDR_ERROR) {
			submir_size = size;
		} else if (size < submir_size) {
			submir_size = size;
		}

		if (options & MDCMD_DOIT) {
			/* store name in namespace */
			if (add_key_name(sp, submirnp, &keynlp, ep) != 0)
				goto out;
		}

		/* setup submirror */
		mmsp->sm_key = submirnp->key;
		mmsp->sm_dev = submirnp->dev;
		mmsp->sm_state = SMS_RUNNING;
		mmsp->sm_timestamp = creation_time;
	}

	/* setup unit */
	mm->c.un_type = MD_METAMIRROR;
	MD_SID(mm) = meta_getminor(mirnp->dev);
	mm->c.un_actual_tb = submir_size;
	mm->c.un_size = offsetof(mm_unit_t, un_smic);
	mm->un_nsm = nsm;
	mm->un_read_option = mirrorp->read_option;
	mm->un_write_option = mirrorp->write_option;
	mm->un_pass_num = mirrorp->pass_num;
	if (mirror_geom(mirrorp, mm, ep) != 0)
		goto out;

	/* fill in the size of the mirror */
	if (options & MDCMD_UPDATE) {
		mirrorp->common.size = mm->c.un_total_blocks;
	}

	/* if we're not doing anything, return success */
	if (! (options & MDCMD_DOIT)) {
		rval = 0;	/* success */
		goto out;
	}

	/* create mirror */
	(void) memset(&set_params, 0, sizeof (set_params));
	/* did the user tell us to generate a large device? */
	create_flag = meta_check_devicesize(mm->c.un_total_blocks);
	if (create_flag == MD_CRO_64BIT) {
		mm->c.un_revision |= MD_64BIT_META_DEV;
		set_params.options = MD_CRO_64BIT;
	} else {
		mm->c.un_revision &= ~MD_64BIT_META_DEV;
		set_params.options = MD_CRO_32BIT;
	}
	set_params.mnum = MD_SID(mm);
	set_params.size = mm->c.un_size;
	set_params.mdp = (uintptr_t)mm;
	MD_SETDRIVERNAME(&set_params, MD_MIRROR, MD_MIN2SET(set_params.mnum));
	if (metaioctl(MD_IOCSET, &set_params, &set_params.mde,
	    mirnp->cname) != 0) {
		(void) mdstealerror(ep, &set_params.mde);
		goto out;
	}
	rval = 0;	/* success */

	/* cleanup, return success */
out:
	Free(mm);
	if (rval != 0) {
		(void) del_key_names(sp, keynlp, NULL);
	}
	metafreenamelist(keynlp);
	if ((rval == 0) && (options & MDCMD_DOIT)) {
		if (invalidate_submirrors(sp, mirnp, ep) != 0)
			rval = -1;
		meta_invalidate_name(mirnp);
	}
	return (rval);
}

/*
 * initialize mirror
 * NOTE: this functions is metainit(1m)'s command line parser!
 */
int
meta_init_mirror(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*uname = argv[0];
	mdname_t	*mirnp = NULL;
	int		old_optind;
	int		c;
	md_mirror_t	*mirrorp = NULL;
	uint_t		smi;
	int		rval = -1;

	/* get mirror name */
	assert(argc > 0);
	if (argc < 1)
		goto syntax;
	if ((mirnp = metaname(spp, uname, META_DEVICE, ep)) == NULL)
		goto out;
	assert(*spp != NULL);
	uname = mirnp->cname;
	if (metachkmeta(mirnp, ep) != 0)
		goto out;

	if (!(options & MDCMD_NOLOCK)) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep) != 0)
			goto out;

		if (meta_check_ownership(*spp, ep) != 0)
			goto out;
	}

	/* see if it exists already */
	if (metagetmiscname(mirnp, ep) != NULL) {
		(void) mdmderror(ep, MDE_UNIT_ALREADY_SETUP,
		    meta_getminor(mirnp->dev), uname);
		goto out;
	} else if (! mdismderror(ep, MDE_UNIT_NOT_SETUP)) {
		goto out;
	} else {
		mdclrerror(ep);
	}
	--argc, ++argv;

	/* grab -m */
	if ((argc < 1) || (strcmp(argv[0], "-m") != 0))
		goto syntax;
	--argc, ++argv;

	if (argc == 0)
		goto syntax;

	/* parse general options */
	optind = 0;
	opterr = 0;
	if (getopt(argc, argv, "") != -1)
		goto options;

	/* allocate mirror */
	mirrorp = Zalloc(sizeof (*mirrorp));

	/* setup common */
	mirrorp->common.namep = mirnp;
	mirrorp->common.type = MD_METAMIRROR;

	/* parse submirrors */
	for (smi = 0; ((argc > 0) && (argv[0][0] != '-') &&
	    (! isdigit(argv[0][0]))); ++smi) {
		md_submirror_t	*mdsm = &mirrorp->submirrors[smi];
		mdname_t	*submirnamep;

		/* check for room */
		if (smi >= NMIRROR) {
			(void) mdmderror(ep, MDE_MIRROR_FULL,
			    meta_getminor(mirnp->dev), uname);
			goto out;
		}

		/* parse submirror name */
		if ((submirnamep = metaname(spp, argv[0],
		    META_DEVICE, ep)) == NULL)
			goto out;
		mdsm->submirnamep = submirnamep;
		--argc, ++argv;
	}
	if (smi == 0) {
		(void) mdmderror(ep, MDE_NSUBMIRS, meta_getminor(mirnp->dev),
					uname);
		goto out;
	}

	/* dangerous n-way mirror creation */
	if ((smi > 1) && (options & MDCMD_PRINT)) {
		md_eprintf(dgettext(TEXT_DOMAIN,
"%s: WARNING: This form of metainit is not recommended.\n"
"The submirrors may not have the same data.\n"
"Please see ERRORS in metainit(1M) for additional information.\n"),
		    uname);
	}

	/* parse mirror options */
	mirrorp->read_option = RD_LOAD_BAL;
	mirrorp->write_option = WR_PARALLEL;
	mirrorp->pass_num = MD_PASS_DEFAULT;
	old_optind = optind = 0;
	opterr = 0;
	while ((c = getopt(argc, argv, "grS")) != -1) {
		switch (c) {
		case 'g':
			if (mirrorp->read_option != RD_LOAD_BAL) {
				(void) mderror(ep, MDE_BAD_RD_OPT, uname);
				goto out;
			}
			mirrorp->read_option = RD_GEOMETRY;
			break;

		case 'r':
			if (mirrorp->read_option != RD_LOAD_BAL) {
				(void) mderror(ep, MDE_BAD_RD_OPT, uname);
				goto out;
			}
			mirrorp->read_option = RD_FIRST;
			break;

		case 'S':
			if (mirrorp->write_option != WR_PARALLEL) {
				(void) mderror(ep, MDE_BAD_WR_OPT, uname);
				goto out;
			}
			mirrorp->write_option = WR_SERIAL;
			break;

		default:
			argc -= old_optind;
			argv += old_optind;
			goto options;
		}
		old_optind = optind;
	}
	argc -= optind;
	argv += optind;

	/* parse pass number */
	if ((argc > 0) && (isdigit(argv[0][0]))) {
		if (name_to_pass_num(uname, argv[0],
		    &mirrorp->pass_num, ep) != 0) {
			goto out;
		}
		--argc, ++argv;
	}

	/* we should be at the end */
	if (argc != 0)
		goto syntax;

	/* create mirror */
	if (meta_create_mirror(*spp, mirrorp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Mirror is setup\n"),
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
	if (mirrorp != NULL)
		meta_free_mirror(mirrorp);
	return (rval);
}

/*
 * reset mirrors
 */
int
meta_mirror_reset(
	mdsetname_t	*sp,
	mdname_t	*mirnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_mirror_t	*mirrorp;
	uint_t		smi;
	int		rval = -1;

	/* should have same set */
	assert(sp != NULL);
	assert((mirnp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev))));

	/* reset all mirrors */
	if (mirnp == NULL) {
		mdnamelist_t	*mirrornlp = NULL;
		mdnamelist_t	*p;

		/* for each mirror */
		rval = 0;
		if (meta_get_mirror_names(sp, &mirrornlp, 0, ep) < 0)
			return (-1);
		for (p = mirrornlp; (p != NULL); p = p->next) {
			/* reset mirror */
			mirnp = p->namep;
			/*
			 * If this is a multi-node set, we send a series
			 * of individual metaclear commands.
			 */
			if (meta_is_mn_set(sp, ep)) {
				if (meta_mn_send_metaclear_command(sp,
				    mirnp->cname, options, 0, ep) != 0) {
					rval = -1;
					break;
				}
			} else {
				if (meta_mirror_reset(sp, mirnp, options,
				    ep) != 0) {
					rval = -1;
					break;
				}
			}
		}

		/* cleanup return success */
		metafreenamelist(mirrornlp);
		return (rval);
	}

	/* check name */
	if (metachkmeta(mirnp, ep) != 0)
		return (-1);

	/* get unit structure */
	if ((mirrorp = meta_get_mirror(sp, mirnp, ep)) == NULL)
		return (-1);

	/* make sure nobody owns us */
	if (MD_HAS_PARENT(mirrorp->common.parent)) {
		return (mdmderror(ep, MDE_IN_USE, meta_getminor(mirnp->dev),
		    mirnp->cname));
	}

	/* clear subdevices cache */
	if (invalidate_submirrors(sp, mirnp, ep) != 0)
		return (-1);

	/* clear metadevice */
	if (meta_reset(sp, mirnp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Mirror is cleared\n"), mirnp->cname);
		(void) fflush(stdout);
	}

	/* clear subdevices */
	if (! (options & MDCMD_RECURSE))
		goto out;
	for (smi = 0; (smi < NMIRROR); ++smi) {
		md_submirror_t	*mdsp = &mirrorp->submirrors[smi];
		mdname_t	*submirnp = mdsp->submirnamep;

		/* skip unused submirrors */
		if (submirnp == NULL) {
			assert(mdsp->state == SMS_UNUSED);
			continue;
		}

		/* make sure we have a metadevice */
		if (! metaismeta(submirnp))
			continue;

		/* clear submirror */
		if (meta_reset_by_name(sp, submirnp, options, ep) != 0)
			rval = -1;
	}

	/* cleanup, return success */
out:
	meta_invalidate_name(mirnp);
	return (rval);
}

/*
 * reports TRUE if any mirror component is in error
 */
int
meta_mirror_anycomp_is_err(mdsetname_t *sp, mdnamelist_t *mirror_names)
{
	mdnamelist_t	*nlp;
	md_error_t	  status	= mdnullerror;
	md_error_t	 *ep		= &status;
	int		  any_errs	= FALSE;

	for (nlp = mirror_names; nlp; nlp = nlp->next) {
		md_mirror_t	*mirrorp;
		int		 smi;

		if ((mirrorp = meta_get_mirror(sp, nlp->namep, ep)) == NULL) {
			any_errs |= TRUE;
			goto out;
		}

		for (smi = 0; smi < NMIRROR; ++smi) {
			md_submirror_t	*mdsp = &mirrorp->submirrors[smi];

			if (mdsp->state &
			    (SMS_COMP_ERRED|SMS_ATTACHED|SMS_OFFLINE)) {
				any_errs |= TRUE;
				goto out;
			}
		}
	}
out:
	if (!mdisok(ep))
		mdclrerror(ep);

	return (any_errs);
}
