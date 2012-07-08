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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * trans operations
 */

#include <meta.h>
#include <meta_basic.h>
#include <sys/lvm/md_trans.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <stddef.h>

extern char *getfullblkname();

/*
 * replace trans
 */

int
meta_trans_replace(mdsetname_t *sp, mdname_t *transnp, mdname_t *oldnp,
    mdname_t *newnp, mdcmdopts_t options, md_error_t *ep)
{
	replace_params_t	params;
	md_dev64_t		old_dev, new_dev;
	daddr_t			new_start_blk, new_end_blk;

	/* should have same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(transnp->dev)));

	new_dev = newnp->dev;
	new_start_blk = newnp->start_blk;
	new_end_blk = newnp->end_blk;

	meta_invalidate_name(transnp);
	/* the old device binding is now established */
	if ((old_dev = oldnp->dev) == NODEV64)
		return (mdsyserror(ep, ENODEV, oldnp->cname));

	if (((strcmp(oldnp->rname, newnp->rname) == 0) &&
	    (old_dev != new_dev))) {
		newnp->dev = new_dev;
		newnp->start_blk = new_start_blk;
		newnp->end_blk = new_end_blk;
	}

	if (add_key_name(sp, newnp, NULL, ep) != 0)
		return (-1);

	(void) memset(&params, 0, sizeof (params));
	params.mnum = meta_getminor(transnp->dev);
	MD_SETDRIVERNAME(&params, MD_TRANS, sp->setno);

	params.cmd = REPLACE_COMP;
	params.old_dev = old_dev;
	params.new_dev = new_dev;
	params.new_key = newnp->key;
	if (metaioctl(MD_IOCREPLACE, &params, &params.mde, NULL) != 0) {
		(void) del_key_name(sp, newnp, ep);
		return (mdstealerror(ep, &params.mde));
	}
	meta_invalidate_name(oldnp);
	meta_invalidate_name(newnp);
	meta_invalidate_name(transnp);

	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: device %s is replaced with %s\n"),
		    transnp->cname, oldnp->cname, newnp->cname);
	}
	return (0);
}



/*
 * FUNCTION:	meta_get_trans_names()
 * INPUT:	sp	- the set name to get trans from
 *		options	- options from the command line
 * OUTPUT:	nlpp	- list of all trans names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	returns a list of all trans in the metadb
 *		for all devices in the specified set
 */
int
meta_get_trans_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	return (meta_get_names(MD_TRANS, sp, nlpp, options, ep));
}

/*
 * free trans unit
 */
void
meta_free_trans(
	md_trans_t	*transp
)
{
	Free(transp);
}

/*
 * get trans (common)
 */
md_trans_t *
meta_get_trans_common(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	int		fast,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = transnp->drivenamep;
	char		*miscname;
	mt_unit_t	*mt;
	md_trans_t	*transp;
	int		gotlog;

	/* must have set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(transnp->dev)));

	/* short circuit */
	if (dnp->unitp != NULL) {
		assert(dnp->unitp->type == MD_METATRANS);
		return ((md_trans_t *)dnp->unitp);
	}

	/* get miscname and unit */
	if ((miscname = metagetmiscname(transnp, ep)) == NULL)
		return (NULL);
	if (strcmp(miscname, MD_TRANS) != 0) {
		(void) mdmderror(ep, MDE_NOT_MT,
		    meta_getminor(transnp->dev), transnp->cname);
		return (NULL);
	}
	if ((mt = (mt_unit_t *)meta_get_mdunit(sp, transnp, ep)) == NULL)
		return (NULL);
	assert(mt->c.un_type == MD_METATRANS);

	/* allocate trans */
	transp = Zalloc(sizeof (*transp));

	/* get common info */
	transp->common.namep = transnp;
	transp->common.type = mt->c.un_type;
	transp->common.state = mt->c.un_status;
	transp->common.capabilities = mt->c.un_capabilities;
	transp->common.parent = mt->c.un_parent;
	transp->common.size = mt->c.un_total_blocks;
	transp->common.user_flags = mt->c.un_user_flags;
	transp->common.revision = mt->c.un_revision;

	/* get master */
	transp->masternamep = metakeyname(&sp, mt->un_m_key, fast, ep);
	if (transp->masternamep == NULL)
		goto out;

	/* get log */
	gotlog = ((mt->un_flags & TRANS_DETACHED) == 0);
	if (gotlog) {
		daddr_t	sblk;

		transp->lognamep = metakeyname(&sp, mt->un_l_key, fast, ep);
		if (transp->lognamep == NULL)
			goto out;

		/* calculate the kernels start block */
		sblk = mt->un_l_pwsblk + mt->un_l_maxtransfer;

		if (getenv("META_DEBUG_START_BLK") != NULL) {
			if (metagetstart(sp, transp->lognamep, ep) ==
			    MD_DISKADDR_ERROR)
				mdclrerror(ep);

			if (transp->lognamep->start_blk > sblk)
				md_eprintf(dgettext(TEXT_DOMAIN,
				    "%s: suspected bad start block [trans]\n"),
				    transp->lognamep->cname);
		}

		/* override any start_blk */
		transp->lognamep->start_blk = sblk;
	}

	/* get flags, etc. */
	transp->flags = mt->un_flags;
	transp->timestamp = mt->un_timestamp;
	transp->log_error = mt->un_l_error;
	transp->log_timestamp = mt->un_l_timestamp;
	transp->log_size = mt->un_l_nblks;
	transp->debug = mt->un_debug;

	/* cleanup, return success */
	Free(mt);
	dnp->unitp = (md_common_t *)transp;
	return (transp);

	/* cleanup, return error */
out:
	Free(mt);
	meta_free_trans(transp);
	return (NULL);
}

/*
 * get trans
 */
md_trans_t *
meta_get_trans(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	md_error_t	*ep
)
{
	return (meta_get_trans_common(sp, transnp, 0, ep));
}

/*
 * check trans for dev
 */
static int
in_trans(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	mdname_t	*np,
	mdchkopts_t	options,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	md_trans_t	*transp;
	mdname_t	*masternp;
	mdname_t	*lognp;

	/* should be in the same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(transnp->dev)));

	/* get unit */
	if ((transp = meta_get_trans(sp, transnp, ep)) == NULL)
		return (-1);

	/* check master */
	masternp = transp->masternamep;
	if ((! metaismeta(masternp)) &&
	    (meta_check_overlap(transnp->cname, np, slblk, nblks,
	    masternp, 0, -1, ep) != 0)) {
		return (-1);
	}

	/* check log */
	if (((lognp = transp->lognamep) != NULL) &&
	    (! (options & MDCHK_ALLOW_LOG)) &&
	    (! metaismeta(lognp))) {
		daddr_t		log_start;
		int		err;

		/* check same drive since metagetstart() can fail */
		if ((err = meta_check_samedrive(np, lognp, ep)) < 0)
			return (-1);

		/* check overlap */
		if (err != 0) {
			if ((log_start = metagetstart(sp, lognp, ep)) ==
			    MD_DISKADDR_ERROR)
				return (-1);
			if (meta_check_overlap(transnp->cname, np, slblk,
			    nblks, lognp, log_start, -1, ep) != 0) {
				return (-1);
			}
		}
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a trans
 */
int
meta_check_intrans(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdchkopts_t	options,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdnamelist_t	*transnlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each trans */
	if (meta_get_trans_names(sp, &transnlp, 0, ep) < 0)
		return (-1);
	for (p = transnlp; (p != NULL); p = p->next) {
		mdname_t	*transnp = p->namep;

		/* check trans */
		if (in_trans(sp, transnp, np, options, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreenamelist(transnlp);
	return (rval);
}

/*
 * check master
 */
int
meta_check_master(
	mdsetname_t	*sp,
	mdname_t	*np,
	int		force,
	md_error_t	*ep
)
{
	mdchkopts_t	options = 0;
	md_common_t	*mdp;

	/* make sure we have a disk */
	if (metachkdisk(np, ep) != 0)
		return (-1);

	/* check to ensure that it is not already in use */
	if ((!force) && meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0) {
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
		if ((mdp = meta_get_unit(sp, np, ep)) == NULL)
			return (-1);

		/*
		 * Since soft partitions may appear at the top or bottom
		 * of the metadevice stack, we check them separately.
		 * A trans may be built on top of a soft partition if
		 * the soft partition has no parent (can't rely on the
		 * MD_CAN_PARENT flag in this case since a soft partition
		 * built on a metadevice clears this flag to prevent nested
		 * configurations).
		 */
		if ((meta_sp_issp(sp, np, ep) == 0) &&
		    (mdp->parent == MD_NO_PARENT))
			return (0);

		if ((! (mdp->capabilities & MD_CAN_PARENT)) ||
		    (mdp->parent != MD_NO_PARENT)) {
			return (mdmderror(ep, MDE_INVAL_UNIT,
			    meta_getminor(np->dev), np->cname));
		}
	}

	/* return success */
	return (0);
}

/*
 * check log
 */
int
meta_check_log(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdchkopts_t	options = (MDCHK_ALLOW_MDDB | MDCHK_ALLOW_LOG);
	md_common_t	*mdp;

	/* make sure we have a disk */
	if (metachkdisk(np, ep) != 0)
		return (-1);

	/* check to ensure that it is not already in use */
	if (meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0) {
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
		if ((mdp = meta_get_unit(sp, np, ep)) == NULL)
			return (-1);

		/*
		 * Since soft partitions may appear at the top or bottom
		 * of the metadevice stack, we check them separately.
		 * A trans may be built on top of a soft partition if
		 * the soft partition has no parent (can't rely on the
		 * MD_CAN_PARENT flag in this case since a soft partition
		 * built on a metadevice clears this flag to prevent nested
		 * configurations).
		 *
		 */
		if ((meta_sp_issp(sp, np, ep) == 0) &&
		    (mdp->parent == MD_NO_PARENT))
			return (0);

		if ((! (mdp->capabilities & MD_CAN_PARENT)) ||
		    ((mdp->parent != MD_NO_PARENT) &&
		    (mdp->parent != MD_MULTI_PARENT))) {
			return (mdmderror(ep, MDE_INVAL_UNIT,
			    meta_getminor(np->dev), np->cname));
		}
	}

	/* return success */
	return (0);
}

/*
 * print trans
 */
static int
trans_print(
	md_trans_t	*transp,
	char		*fname,
	FILE		*fp,
	md_error_t	*ep
)
{
	int		rval = -1;

	/* print name and -t */
	if (fprintf(fp, "%s -t", transp->common.namep->cname) == EOF)
		goto out;

	/* print master */
	/*
	 * If the path is our standard /dev/rdsk or /dev/md/rdsk
	 * then just print out the cxtxdxsx or the dx, metainit
	 * will assume the default, otherwise we need the full
	 * pathname to make sure this works as we intend.
	 */
	if ((strstr(transp->masternamep->rname, "/dev/rdsk") == NULL) &&
	    (strstr(transp->masternamep->rname, "/dev/md/rdsk") == NULL) &&
	    (strstr(transp->masternamep->rname, "/dev/td/") == NULL)) {
		/* not standard path, print full pathname */
		if (fprintf(fp, " %s", transp->masternamep->rname) == EOF)
			goto out;
	} else {
		/* standard path, print ctds or d number */
		if (fprintf(fp, " %s", transp->masternamep->cname) == EOF)
			goto out;
	}


	/* print log */
	if (transp->lognamep != NULL) {
		/*
		 * If the path is our standard /dev/rdsk or /dev/md/rdsk
		 * then just print out the cxtxdxsx or the dx, metainit
		 * will assume the default, otherwise we need the full
		 * pathname to make sure this works as we intend.
		 */
		if ((strstr(transp->lognamep->rname, "/dev/rdsk") == NULL) &&
		    (strstr(transp->lognamep->rname, "/dev/md/rdsk") == NULL) &&
		    (strstr(transp->lognamep->rname, "/dev/td/") == NULL)) {
			/* not standard path, print full pathname */
			if (fprintf(fp, " %s", transp->lognamep->rname) == EOF)
				goto out;
		} else {
			/* standard path */
			if (fprintf(fp, " %s", transp->lognamep->cname) == EOF)
				goto out;
		}
	}

	/* print terminating newline */
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
 * convert flags to repair action
 */

char *
mt_flags_to_action(
	md_trans_t *transp
)
{
	int	 len;
	char	*actionp	= NULL;
	int	 err		= -1;

	if (!transp) {
		goto out;
	}

	/*
	 * if in any of these states, the log_error word is not (yet) meaningful
	 */
	if (transp->flags & (TRANS_DETACHED|TRANS_DETACHING|TRANS_ATTACHING)) {
		goto out;
	}

	if (transp->log_error & LDL_ANYERROR) {
		char *fix_msg = dgettext(TEXT_DOMAIN,
		    "    To Fix: Please refer to the log device's status.\n");

		if ((len = strlen(fix_msg)) <= 0) {
			goto out;
		}
		if (!(actionp = Zalloc(len+1))) {
			goto out;
		}
		if (strncpy(actionp, fix_msg, len + 1) != actionp) {
			goto out;
		}
	}
	err = 0;
out:
	if (err != 0) {
		if (actionp) {
			Free(actionp);
			actionp = NULL;
		}
	}
	return (actionp);
}

/*
 * convert log state to repair action
 */
char *
mt_l_error_to_action(
	mdsetname_t	*sp,
	mdnamelist_t	*transnlp,
	mdname_t	*lognamep,
	md_error_t	*ep
)
{
	char		 umnt_msg[1024];
	char		 fsck_msg[1024];
	char		 mnt_msg[1024];
	mdnamelist_t	*p;
	md_trans_t	*tp;
	int		 rc;
	int		 len		= 0;
	char		*rmsg		= NULL;
	char		*mp		= NULL;
	bool_t		 is_mounted	= FALSE;
	bool_t		 any_in_error	= FALSE;
	int		 only_fsck	= TRUE;

	(void) memset(umnt_msg, 0, sizeof (umnt_msg));
	(void) memset(fsck_msg, 0, sizeof (fsck_msg));
	(void) memset(mnt_msg, 0, sizeof (mnt_msg));

	/*
	 * If a the trans devices listed in transnlp contain
	 * devices which are in error and are sub-mount points
	 * of each other, than it would need to be reverse sorted.
	 * When this actually occurs, and customers find the usage
	 * message insufficiently clear, then we should take the
	 * hit to sort it.
	 */

	/*
	 * this preliminary loop is necessary to keep the
	 * fsck message greppable, if possible
	 */
	for (p = transnlp; ((p != NULL) && (only_fsck == TRUE)); p = p->next) {

		if ((tp = meta_get_trans(sp, p->namep, ep)) == NULL) {
			goto out;
		}

		if (!(tp->log_error & LDL_ANYERROR)) {
			continue;
		}

		if ((tp->lognamep == NULL) ||
		    (strcmp(lognamep->bname, tp->lognamep->bname) != 0)) {
			continue;
		}

		mdclrerror(ep);
		is_mounted = (meta_check_inuse(sp,
		    p->namep, MDCHK_MOUNTED, ep) != 0);

		if (!mdisok(ep) && mdisuseerror(ep, MDE_IS_MOUNTED)) {
			goto out;
		}

		mdclrerror(ep);
		mp = meta_get_mountp(sp, p->namep, ep);

		if (!mdisok(ep)) {
			goto out;
		}

		if (is_mounted) {
			if (!mp) {
				goto out;
			}
			only_fsck = FALSE;

			/*
			 * not greppable; there must be multiple commands, so
			 * add preliminary newline so the formatting is uniform
			 */
			if (sprintf(umnt_msg, "\n") == EOF) {
				goto out;
			}

		}

		if (mp) {
			Free(mp);
			mp = NULL;
		}
	}

	/*
	 * although the log may either be in error or hard-error
	 * states, the action is the same; unmount, fsck and remount
	 * all fs associated with this log
	 */
	for (p = transnlp; (p != NULL); p = p->next) {

		if ((tp = meta_get_trans(sp, p->namep, ep)) == NULL) {
			goto out;
		}

		if (!(tp->log_error & LDL_ANYERROR)) {
			continue;
		}

		if ((tp->lognamep == NULL) ||
		    (strcmp(lognamep->bname, tp->lognamep->bname) != 0)) {
			continue;
		}

		mdclrerror(ep);
		is_mounted = (meta_check_inuse(sp,
		    p->namep, MDCHK_MOUNTED, ep) != 0);

		if (!mdisok(ep) && mdisuseerror(ep, MDE_IS_MOUNTED)) {
			goto out;
		}

		mdclrerror(ep);
		mp = meta_get_mountp(sp, p->namep, ep);

		if (!mdisok(ep)) {
			goto out;
		}

		if (is_mounted) {
			if (!mp) {
				goto out;
			}
		}

		if (is_mounted) {
			rc = snprintf(umnt_msg, sizeof (umnt_msg),
			    "%s            umount %s\n", umnt_msg, mp);

			if (rc < 0) {
				goto out;
			}
		}

		rc = snprintf(fsck_msg, sizeof (fsck_msg), "%s %s",
		    (any_in_error) ? fsck_msg :
		    ((only_fsck) ? "fsck" : "            fsck"),
		    p->namep->rname);
		if (rc < 0) {
			goto out;
		}

		if (is_mounted) {
			rc = snprintf(mnt_msg, sizeof (mnt_msg),
			    "%s            mount %s %s\n",
			    mnt_msg, p->namep->bname, mp);

			if (rc < 0) {
				goto out;
			}
		}

		if (mp) {
			Free(mp);
			mp = NULL;
		}

		any_in_error |= TRUE;
	}

	if (!any_in_error) {
		goto out;
	}

	len = strlen(umnt_msg) + strlen(fsck_msg) + strlen(mnt_msg) +
	    (only_fsck? 1: 0) + 1;
	if (!(rmsg = Zalloc(len))) {
		len = 0;
		goto out;
	}
	rc = snprintf(rmsg, len, "%s%s%s%s", umnt_msg, fsck_msg,
	    !only_fsck? "\n": "", mnt_msg);
	if (rc == EOF) {
		goto out;
	}

out:
	if (mp) {
		Free(mp);
		mp = NULL;
	}
	if (len == 0 && rmsg) {
		Free(rmsg);
		rmsg = NULL;
	}

	return (rmsg);
}

/*
 * printable log state
 */
char *
mt_l_error_to_name(
	md_trans_t	*transp,
	md_timeval32_t	*tvp,
	uint_t		tstate	/* Errored tstate flags */
)
{
	mt_l_error_t	log_error = transp->log_error;

	/* grab time */
	if (tvp != NULL)
		*tvp = transp->log_timestamp;

	if (tstate != 0) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* return state */
	if (log_error & LDL_ERROR) {
		return (dgettext(TEXT_DOMAIN, "Error"));
	} else if (log_error & LDL_HERROR) {
		return (dgettext(TEXT_DOMAIN, "Hard Error"));
	} else {
		return (dgettext(TEXT_DOMAIN, "Okay"));
	}
}

/*
 * printable trans state
 */
char *
mt_flags_to_name(
	md_trans_t	*transp,
	md_timeval32_t	*tvp,
	uint_t		tstate	/* Errored tstate flags */
)
{
	/* grab time */
	if (tvp != NULL)
		*tvp = transp->timestamp;

	if (tstate != 0) {
		return (dgettext(TEXT_DOMAIN, "Unavailable"));
	}

	/* return state */
	if (transp->flags & TRANS_DETACHED)
		return (dgettext(TEXT_DOMAIN, "Detached"));
	else if (transp->flags & TRANS_DETACHING)
		return (dgettext(TEXT_DOMAIN, "Detaching"));
	else if (transp->flags & TRANS_ATTACHING)
		return (dgettext(TEXT_DOMAIN, "Attaching"));
	return (mt_l_error_to_name(transp, tvp, tstate));
}

/*
 * report trans
 */
static int
trans_report(
	mdsetname_t	*sp,
	md_trans_t	*transp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	char		*mt_state;
	md_timeval32_t	tv;
	char		*timep;
	int		rval = -1;
	char		*actionp = NULL;
	char 		*devid = "";
	mdname_t	*didnp = NULL;
	ddi_devid_t	dtp;
	uint_t		tstate = 0;

	/* print header */
	if (options & PRINT_HEADER) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: Trans"
		    " (Feature replaced see message below)\n"),
		    transp->common.namep->cname) == EOF) {
			goto out;
		}
	}

	/* print state */
	if (metaismeta(transp->common.namep)) {
		if (meta_get_tstate(transp->common.namep->dev, &tstate, ep)
		    != 0)
			goto out;
	}
	mt_state = mt_flags_to_name(transp, &tv, tstate & MD_DEV_ERRORED);
	if (options & PRINT_TIMES) {
		timep = meta_print_time(&tv);
	} else {
		timep = "";
	}
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    State: %-12s %s\n"),
	    mt_state, timep) == EOF) {
		goto out;
	}

	if ((tstate & MD_DEV_ERRORED) == 0) {
		actionp = mt_flags_to_action(transp);
		if (actionp) {
			if (fprintf(fp, "%s", actionp) == EOF) {
				goto out;
			}
			Free(actionp);
			actionp = NULL;
		}
	}

	/* debug stuff */
	if (transp->debug) {
		if (fprintf(fp,
		    "    Debug Modes:%s%s%s%s%s%s%s%s%s%s%s\n",
		    (transp->debug & MT_TRANSACT) ? " TRANSACT" : "",
		    (transp->debug & MT_MATAMAP) ? " METADATA" : "",
		    (transp->debug & MT_WRITE_CHECK) ?  " WRITES" : "",
		    (transp->debug & MT_LOG_WRITE_CHECK) ? " LOGWRITES" : "",
		    (transp->debug & MT_CHECK_MAP) ? " MAP" : "",
		    (transp->debug & MT_TRACE) ? " TRACE" : "",
		    (transp->debug & MT_SIZE) ? " SIZE" : "",
		    (transp->debug & MT_NOASYNC) ? " NOASYNC" : "",
		    (transp->debug & MT_FORCEROLL) ? " FORCEROLL" : "",
		    (transp->debug & MT_SCAN) ? " SCAN" : "",
		    (transp->debug & MT_PREWRITE) ? " PREWRITE" : "")
		    == EOF) {
			goto out;
		}
	}

	/* print size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %lld blocks (%s)\n"),
	    transp->common.size,
	    meta_number_to_string(transp->common.size, DEV_BSIZE)) == EOF) {
		goto out;
	}


	/* print master */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Master Device: %s\n"),
	    transp->masternamep->cname) == EOF) {
		goto out;
	}

	/* print log */
	if (transp->lognamep != NULL) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Logging Device: %s\n"),
		    transp->lognamep->cname) == EOF) {
			goto out;
		}
	}

	/* add extra line */
	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* print master details if regular device */
	if (! metaismeta(transp->masternamep)) {
		daddr_t	start_blk = 0;
		char	*has_mddb_str = dgettext(TEXT_DOMAIN, "No");
		int	len;

		/*
		 * Building a format string on the fly that will
		 * be used in (f)printf. This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		len = strlen(transp->masternamep->cname) + 2;
		len = max(len, strlen(dgettext(TEXT_DOMAIN, "Master Device")));

		/* print header */
		if (fprintf(fp,
		    "\t%-*.*s %-12.12s %-5.5s %s\n",
		    len, len,
		    dgettext(TEXT_DOMAIN, "Master Device"),
		    dgettext(TEXT_DOMAIN, "Start Block"),
		    dgettext(TEXT_DOMAIN, "Dbase"),
		    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
			goto out;
		}

		/* populate the key in the name_p structure */
		if ((didnp = metadevname(&sp,
		    transp->masternamep->dev, ep)) == NULL) {
			return (-1);
		}

	    /* determine if devid does NOT exist */
		if (options & PRINT_DEVID)
			if ((dtp = meta_getdidbykey(sp->setno,
			    getmyside(sp, ep), didnp->key, ep)) == NULL) {
				devid = dgettext(TEXT_DOMAIN, "No ");
			} else {
				devid = dgettext(TEXT_DOMAIN, "Yes");
				free(dtp);
			}

		/* print info */
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		if (fprintf(fp, "\t%-*s %8ld     %-5.5s %s\n", len,
		    transp->masternamep->cname,
		    start_blk, has_mddb_str, devid) == EOF) {
			goto out;
		}
		/* add extra line */
		if (fprintf(fp, "\n") == EOF)
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
 * print/report trans
 */
int
meta_trans_print(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	mdnamelist_t	**nlistpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	int		*meta_print_trans_msgp, /* NULL if transnp != NULL */
	mdnamelist_t	**lognlpp,
	md_error_t	*ep
)
{
	md_trans_t	*transp;
	mdname_t	*lognamep;

	/* should have same set */
	assert(sp != NULL);

	/* print all transs */
	if (transnp == NULL) {
		mdnamelist_t	*nlp = NULL;
		mdnamelist_t	*p;
		int		cnt;
		int		rval = 0;

		/* get list */
		if ((cnt = meta_get_trans_names(sp, &nlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recurse */
		for (p = nlp; (p != NULL); p = p->next) {
			mdname_t	*np = p->namep;

			if (meta_trans_print(sp, np, nlistpp, fname, fp,
			    options, meta_print_trans_msgp, lognlpp, ep) != 0)
				rval = -1;
		}

		if (meta_print_trans_msgp)
			*meta_print_trans_msgp = 1;

		/* cleanup, return success */
		metafreenamelist(nlp);
		return (rval);
	}


	/* get unit structure */
	if ((transp = meta_get_trans_common(sp, transnp,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* save unique log */
	if ((lognlpp != NULL) &&
	    ((lognamep = transp->lognamep) != NULL)) {
		mdnamelist_t	*p;

		for (p = *lognlpp; (p != NULL); p = p->next) {
			if (strcmp(lognamep->bname, p->namep->bname) == 0)
				break;
		}
		if (p == NULL)
			(void) metanamelist_append(lognlpp, lognamep);
	}

	/* check for parented */
	if ((! (options & PRINT_SUBDEVS)) &&
	    (MD_HAS_PARENT(transp->common.parent))) {
		return (0);
	}

	/* can't have a large trans or descriptive name trans */
	if (!(options & (PRINT_LARGEDEVICES | PRINT_FN))) {
		/* print appropriate detail */
		if (options & PRINT_SHORT) {
			if (trans_print(transp, fname, fp, ep) != 0)
				return (-1);
		} else {
			if (trans_report(sp, transp, fname, fp, options, ep)
			    != 0)
				return (-1);
		}
	}

	/* print underlying metadevices, log is later */
	if (metaismeta(transp->masternamep)) {
		if (meta_print_name(sp, transp->masternamep, nlistpp, fname,
		    fp, (options | PRINT_HEADER | PRINT_SUBDEVS), NULL, ep)
		    != 0) {
			return (-1);
		}
	}

	/* return success */
	return (0);
}

/*
 * print log
 */
static int
log_print(
	mdsetname_t	*sp,
	mdname_t	*lognamep,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	mdnamelist_t	*nlp = NULL;

	/* metadevice info */
	if (metaismeta(lognamep)) {
		return (meta_print_name(sp, lognamep, &nlp, fname, fp,
		    options, NULL, ep));
	}

	/* regular device info */
	return (0);
}

/*
 * report log
 */
static int
log_report(
	mdsetname_t	*sp,
	mdname_t	*lognamep,
	mdnamelist_t	**nlistpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	mdnamelist_t	*transnlp,
	md_error_t	*ep
)
{
	md_trans_t	*transp = NULL;
	mdnamelist_t	*p;
	char		*ml_state;
	md_timeval32_t	tv;
	char		*timep;
	char		*actionp = NULL;
	int		rval = -1;
	char		*devid = " ";
	mdname_t	*didnp = NULL;
	ddi_devid_t	dtp;
	uint_t		tstate = 0;

	for (p = transnlp; (p != NULL); p = p->next) {
		md_trans_t	*tp;

		if ((tp = meta_get_trans(sp, p->namep, ep)) == NULL)
			return (-1);
		if ((tp->lognamep != NULL) &&
		    (strcmp(lognamep->bname, tp->lognamep->bname) == 0)) {
			transp = tp;	/* save any parent trans */
		}
	}

	/* we must have at least one trans */
	assert(transp != NULL);
	if (transp == NULL) {
		rval = 0;
		goto out;
	}

	if ((options & PRINT_LARGEDEVICES) &&
	    (transp->log_size <= MD_MAX_BLKS_FOR_SMALL_DEVS)) {
		rval = 0;
		goto out;
	}

	/* print header and trans devices, collect log_error and size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: Logging device for"),
	    lognamep->cname) == EOF) {
		goto out;
	}

	if ((transp->lognamep != NULL) &&
	    (strcmp(lognamep->bname, transp->lognamep->bname) == 0)) {
		if (fprintf(fp, " %s", transp->common.namep->cname)
		    == EOF) {
			goto out;
		}
	}
	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* print state */
	if (metaismeta(transp->lognamep)) {
		if (meta_get_tstate(transp->lognamep->dev, &tstate, ep) != 0)
			return (-1);
	}
	ml_state = mt_l_error_to_name(transp, &tv, tstate & MD_DEV_ERRORED);
	if (options & PRINT_TIMES) {
		timep = meta_print_time(&tv);
	} else {
		timep = "";
	}
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    State: %-12s %s\n"),
	    ml_state, timep) == EOF) {
		goto out;
	}

	if ((tstate & MD_DEV_ERRORED) == 0) {
		actionp = mt_l_error_to_action(sp, transnlp, lognamep, ep);
		if (actionp) {
			if (fprintf(fp, dgettext(TEXT_DOMAIN,
			    "    Invoke: %s\n"), actionp) == EOF) {
				goto out;
			}
			Free(actionp);
			actionp = NULL;
		}
	}

	/* print size */
	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %ld blocks (%s)\n"),
	    transp->log_size,
	    meta_number_to_string(transp->log_size, DEV_BSIZE)) == EOF) {
		goto out;
	}

	/* MD_DEBUG stuff */
	if (options & PRINT_DEBUG) {
		mdname_t	*transnp = transp->common.namep;
		mt_unit_t	*mt;
		daddr_t		blksinuse, head, tail, nblks, eblk, sblk;
		int		percent;

		if ((mt = (mt_unit_t *)meta_get_mdunit(sp, transnp, ep))
		    == NULL) {
			return (-1);
		}
		assert(mt->c.un_type == MD_METATRANS);

		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Transfer Size: %d blocks\n"),
		    mt->un_l_maxtransfer) == EOF) {
			Free(mt);
			goto out;
		}

		head = mt->un_l_head;
		tail = mt->un_l_tail;
		sblk = mt->un_l_sblk;
		nblks = mt->un_l_nblks;
		eblk = sblk + nblks;
		if (head <= tail)
			blksinuse = tail - head;
		else
			blksinuse = (eblk - head) + (tail - sblk);

		percent = ((u_longlong_t)blksinuse * 100) / nblks;
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Full: %d%% (%ld of %ld blocks)\n"),
		    percent, blksinuse, nblks) == EOF) {
			Free(mt);
			goto out;
		}

		percent = ((u_longlong_t)mt->un_l_resv * 100) /
		    mt->un_l_maxresv;
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    Reserved: %d%% (%ud of %ud bytes)\n"),
		    percent, mt->un_l_resv, mt->un_l_maxresv) == EOF) {
			Free(mt);
			goto out;
		}
		Free(mt);
	}

	/* add extra line */
	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* print log details */
	if (metaismeta(lognamep)) {
		if (meta_print_name(sp, lognamep, nlistpp, fname, fp,
		    options, NULL, ep) != 0) {
			return (-1);
		}
	} else {
		daddr_t		start_blk;
		int		has_mddb;
		char		*has_mddb_str;
		int		len;

		/*
		 * Building a format string on the fly that will
		 * be used in (f)printf. This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		len = strlen(lognamep->cname) + 2;
		len = max(len, strlen(dgettext(TEXT_DOMAIN, "Logging Device")));
		/* print header */
		if (fprintf(fp,
		    "\t%-*.*s %-12.12s %-5.5s %s\n",
		    len, len,
		    dgettext(TEXT_DOMAIN, "Logging Device"),
		    dgettext(TEXT_DOMAIN, "Start Block"),
		    dgettext(TEXT_DOMAIN, "Dbase"),
		    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
			goto out;
		}
		/* get info */
		if ((start_blk = metagetstart(sp, lognamep, ep)) ==
		    MD_DISKADDR_ERROR) {
			return (-1);
		}
		if ((has_mddb = metahasmddb(sp, lognamep, ep)) < 0) {
			return (-1);
		}
		if (has_mddb)
			has_mddb_str = dgettext(TEXT_DOMAIN, "Yes");
		else
			has_mddb_str = dgettext(TEXT_DOMAIN, "No");

		/* populate the key in the name_p structure */
		if ((didnp = metadevname(&sp, lognamep->dev, ep)) == NULL) {
			return (-1);
		}

	    /* determine if devid does NOT exist */
		if (options & PRINT_DEVID)
			if ((dtp = meta_getdidbykey(sp->setno,
			    getmyside(sp, ep), didnp->key, ep)) == NULL) {
				devid = dgettext(TEXT_DOMAIN, "No ");
			} else {
				devid = dgettext(TEXT_DOMAIN, "Yes");
				free(dtp);
			}

		/* print info */
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		if (fprintf(fp, "\t%-*s %8ld     %-5.5s %s\n",
		    len, lognamep->cname, start_blk,
		    has_mddb_str, devid) == EOF) {
			goto out;
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
 * print/report logs
 */
int
meta_logs_print(
	mdsetname_t	*sp,
	mdnamelist_t	*lognlp,
	mdnamelist_t	**nlistpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	mdnamelist_t	*transnlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* must have a set */
	assert(sp != NULL);

	/* get trans devices */
	if (lognlp == NULL)
		return (0);

	if (! (options & PRINT_SHORT))
		if (meta_get_trans_names(sp, &transnlp, options, ep) < 0)
			return (-1);

	/* print all logs */
	options |= PRINT_SUBDEVS;
	for (p = lognlp; (p != NULL); p = p->next) {
		mdname_t	*lognamep = p->namep;

		/* print appropriate detail */
		if (options & PRINT_SHORT) {
			if (log_print(sp, lognamep, fname, fp, options,
			    ep) != 0) {
				rval = -1;
			}
		} else {
			if (log_report(sp, lognamep, nlistpp, fname, fp,
			    options, transnlp, ep) != 0) {
				rval = -1;
			}
		}
	}

	/* cleanup, return success */
out:
	metafreenamelist(transnlp);
	return (rval);
}

/*
 * meta_lockfs_common -- common lock and unlock code
 *
 * Normally this routine will return a 0 for success. Even if
 * lockfs wasn't able to lock down the filesystem. The reason
 * for this is that the master device can be in an errored state
 * and the lock can't be obtained. We don't want to prevent
 * possible recovery in this case and it's not likely any activity
 * will be occurring. If the filesystem is healthy with activity
 * lockfs will successfully lock the filesystem and return an
 * error code of 0.
 *
 * The one case where this routine returns a non-zero value would
 * be if we can't determine the outcome of the lockfs. This should
 * never occur because we don't catch signals that could cause
 * waitpid() to prematurely return.
 */
static int
meta_lockfs_common(mdname_t *fs, void **cookie, int lockit)
{
	char		*blkname;
	FILE		*m;
	struct mnttab	tab_wildcard, tab_match;
	pid_t		pid;
	int		lock_exit;

	(void) memset(&tab_wildcard, 0, sizeof (tab_wildcard));
	(void) memset(&tab_match, 0, sizeof (tab_match));

	if ((blkname = fs->bname) == NULL)
		blkname = getfullblkname(fs->cname);

	tab_wildcard.mnt_special = blkname;

	if ((m = fopen(MNTTAB, "r")) == NULL) {
		/*
		 * No mnttab means nothing is mounted
		 */
		*cookie = 0;
		return (0);
	}

	if (getmntany(m, &tab_match, &tab_wildcard)) {
		/*
		 * No match in mnttab so we're not mounted ... at least
		 * nothing better be mounted.
		 */
		*cookie = 0;
		return (0);
	}

	(void) fclose(m);

	switch (pid = fork()) {
	case -1:
		/*
		 * We've got some major trouble here and shouldn't
		 * continue. The user needs to clear up the problems
		 * that the system currently has before proceeding
		 * to detach the log.
		 */
		(void) printf(dgettext(TEXT_DOMAIN, "failed to fork lockfs\n"));
		*cookie = 0;
		return (1);

	case 0:
		(void) execl("/usr/sbin/lockfs", "lockfs", lockit ? "-w" : "-u",
		    "-c", "Solaris Volume Manager detach lock",
		    tab_match.mnt_mountp, 0);
		/*
		 * Shouldn't reach here, but if this code is run on
		 * a release that doesn't have lockfs return an error
		 * code so that the -f (force) option could be used
		 * by metadetach.
		 */
		exit(1);

	default:
		if (waitpid(pid, &lock_exit, 0) != pid) {
			/*
			 * We couldn't get status regarding the
			 * outcome of the lockfs command. We should
			 * attempt to unlock the filesystem though.
			 * Return an error code so that if the user
			 * is trying to force the detach make them
			 * clear up this problem first.
			 */
			*cookie = (void *)1;
			return (1);
		}

		*cookie = (void *)1;
		return (0);
	}
}

/*
 * meta_lockfs - if mounted, lock a given device against writes
 *
 * See comment section for meta_lockfs_common
 */
static int
meta_lockfs(mdname_t *fs, void **cookie)
{
	return (meta_lockfs_common(fs, cookie, 1));
}

/*
 * meta_unlockfs - if mounted, unlock the filesystem if previously locked
 *
 * See comment section for meta_lockfs_common
 */
static void
meta_unlockfs(mdname_t *fs, void **cookie)
{
	/*
	 * Simple time saver. We could always try to unlock
	 * the filesystem, that takes time a resources.
	 */
	if (*cookie == (void *)1)
		(void) meta_lockfs_common(fs, cookie, 0);
}

/*
 * meta_trans_detach -- detach log from trans device
 */
int
meta_trans_detach(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	mdcmdopts_t	options,
	int		*delayed,
	md_error_t	*ep
)
{
	int		force = ((options & MDCMD_FORCE) ? 1 : 0);
	md_i_get_t	detach;
	md_trans_t	*transp;
	mdname_t	*lognp;
	void		*lock_cookie;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(transnp->dev)));

	/* check name */
	if (metachkmeta(transnp, ep) != 0)
		return (-1);

	/* save log name */
	if ((transp = meta_get_trans(sp, transnp, ep)) == NULL)
		return (-1);
	if ((lognp = transp->lognamep) == NULL)
		return (mdmderror(ep, MDE_NO_LOG, meta_getminor(transnp->dev),
		    transnp->cname));

	/*
	 * If trans device is mounted lock the filesystem
	 * against writes and mod time updates.
	 */
	if (force && meta_lockfs(transnp, &lock_cookie)) {
		/*
		 * This device is mounted and we were unable
		 * lock the device. Data corruption can occur
		 * if we don't lock the device before removing
		 * the log so bail out here.
		 * NOTE: There's one case were the exist status
		 * of lockfs could have been lost yet the command
		 * could have run. We should try to unlock the filesystem
		 * before returning.
		 */
		meta_unlockfs(transnp, &lock_cookie);
		return (mdmderror(ep, MDE_UNKNOWN_TYPE,
		    meta_getminor(transnp->dev), transnp->cname));
	}

	/* detach log */
	*delayed = 0;
	(void) memset(&detach, 0, sizeof (detach));
	detach.id = meta_getminor(transnp->dev);
	MD_SETDRIVERNAME(&detach, MD_TRANS, sp->setno);
	detach.size = force;
	if (metaioctl(MD_IOC_TRANS_DETACH, &detach, &detach.mde, NULL) != 0) {
		/* delayed detach */
		if ((force) && (mdissyserror(&detach.mde, EBUSY))) {
			*delayed = 1;
			mdclrerror(&detach.mde);
		} else {
			meta_unlockfs(transnp, &lock_cookie);
			return (mdstealerror(ep, &detach.mde));
		}
	}

	/*
	 * Unlock the filesystem
	 */
	meta_unlockfs(transnp, &lock_cookie);

	/* clear cache */
	meta_invalidate_name(lognp);
	meta_invalidate_name(transnp);

	/* let em know */
	if (options & MDCMD_PRINT) {
		if (*delayed) {
			(void) printf(dgettext(TEXT_DOMAIN,
"%s: logging device %s will be detached at unmount or reboot\n"),
			    transnp->cname, lognp->cname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: logging device %s is detached\n"),
			    transnp->cname, lognp->cname);
		}
		(void) fflush(stdout);
	}

	/* return success */
	return (0);
}

/*
 * reset trans
 */
int
meta_trans_reset(
	mdsetname_t	*sp,
	mdname_t	*transnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_trans_t	*transp;
	int		rval = -1;

	/* should have a set */
	assert(sp != NULL);
	assert((transnp == NULL) ||
	    (sp->setno == MD_MIN2SET(meta_getminor(transnp->dev))));

	/* reset all trans */
	if (transnp == NULL) {
		mdnamelist_t	*transnlp = NULL;
		mdnamelist_t	*p;

		/* for each trans */
		rval = 0;
		if (meta_get_trans_names(sp, &transnlp, 0, ep) < 0)
			return (-1);
		for (p = transnlp; (p != NULL); p = p->next) {
			/* reset trans */
			transnp = p->namep;
			if (meta_trans_reset(sp, transnp, options, ep) != 0) {
				rval = -1;
				break;
			}
		}

		/* cleanup, return success */
		metafreenamelist(transnlp);
		return (rval);
	}

	/* check name */
	if (metachkmeta(transnp, ep) != 0)
		return (-1);
	/* get unit structure */
	if ((transp = meta_get_trans(sp, transnp, ep)) == NULL)
		return (-1);

	/* make sure nobody owns us */
	if (MD_HAS_PARENT(transp->common.parent)) {
		return (mdmderror(ep, MDE_IN_USE, meta_getminor(transnp->dev),
		    transnp->cname));
	}

	/* clear subdevices cache */
	meta_invalidate_name(transp->masternamep);
	if (transp->lognamep)
		meta_invalidate_name(transp->lognamep);

	/* clear metadevice */
	if (meta_reset(sp, transnp, options, ep) != 0)
		goto out;
	rval = 0;	/* success */

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN, "%s: Trans is cleared\n"),
		    transnp->cname);
		(void) fflush(stdout);
	}

	/* clear subdevices */
	if (! (options & MDCMD_RECURSE))
		goto out;
	if (metaismeta(transp->masternamep)) {
		mdname_t	*masternp = transp->masternamep;

		if (meta_reset_by_name(sp, masternp, options, ep) != 0)
			rval = -1;
	}
	/* (multi-parented) log will be cleared later */

	/* cleanup, return success */
out:
	meta_invalidate_name(transnp);
	return (rval);
}
