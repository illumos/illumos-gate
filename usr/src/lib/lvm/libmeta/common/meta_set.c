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
 * Metadevice diskset interfaces
 */

#include "meta_set_prv.h"
#include <meta.h>
#include <metad.h>
#include <mdmn_changelog.h>
#include <sys/lvm/md_crc.h>
#include <sys/utsname.h>
#include <sdssc.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>
extern	char	*blkname(char *);

static md_drive_desc *
dr2drivedesc(
	mdsetname_t	*sp,
	side_t		sideno,
	int		flags,
	md_error_t	*ep
)
{
	md_set_record	*sr;
	md_drive_record	*dr;
	mddrivename_t	*dnp;
	md_drive_desc	*dd_head = NULL;
	md_set_desc	*sd;

	if (flags & MD_BYPASS_DAEMON) {
		if ((sr = metad_getsetbynum(sp->setno, ep)) == NULL)
			return (NULL);
		sd = metaget_setdesc(sp, ep);
		sideno = getnodeside(mynode(), sd);
		sp = metafakesetname(sp->setno, sr->sr_setname);
	} else {
		if ((sr = getsetbyname(sp->setname, ep)) == NULL)
			return (NULL);
	}

	assert(sideno != MD_SIDEWILD);

	/*
	 * WARNING:
	 * The act of getting the dnp from the namespace means that we
	 * will get the devid of the disk as recorded in the namespace.
	 * This devid has the potential to be stale if the disk is being
	 * replaced via a rebind, this means that any code that relies
	 * on any of the dnp information should take the appropriate action
	 * to preserve that information. For example in the rebind code the
	 * devid of the new disk is saved off and then copied back in once
	 * the code that has called this function has completed.
	 */
	for (dr = sr->sr_drivechain; dr != NULL; dr = dr->dr_next) {
		if ((dnp = metadrivename_withdrkey(sp, sideno, dr->dr_key,
		    flags, ep)) == NULL) {
			if (!(flags & MD_BYPASS_DAEMON))
				free_sr(sr);
			metafreedrivedesc(&dd_head);
			return (NULL);
		}

		(void) metadrivedesc_append(&dd_head, dnp, dr->dr_dbcnt,
		    dr->dr_dbsize, dr->dr_ctime, dr->dr_genid, dr->dr_flags);
	}

	if (!(flags & MD_BYPASS_DAEMON)) {
		free_sr(sr);
	}
	return (dd_head);
}

static int
get_sidenmlist(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	md_error_t	*ep
)
{
	md_set_desc	*sd;
	mdsidenames_t	*sn, **sn_next;
	int		i;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	metaflushsidenames(dnp);
	sn_next = &dnp->side_names;
	if (MD_MNSET_DESC(sd)) {
		/*
		 * Only get sidenames for this node since
		 * that is the only side information stored in
		 * the local mddb for a multi-node diskset.
		 */
		if (sd->sd_mn_mynode) {
			sn = Zalloc(sizeof (*sn));
			sn->sideno = sd->sd_mn_mynode->nd_nodeid;
			if ((sn->cname = meta_getnmentbykey(MD_LOCAL_SET,
			    sn->sideno, dnp->side_names_key, &sn->dname,
			    &sn->mnum, NULL, ep)) == NULL) {
				if (sn->dname != NULL)
					Free(sn->dname);
				Free(sn);
				return (-1);
			}

			/* Add to the end of the linked list */
			assert(*sn_next == NULL);
			*sn_next = sn;
			sn_next = &sn->next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			sn = Zalloc(sizeof (*sn));
			sn->sideno = i;
			if ((sn->cname = meta_getnmentbykey(MD_LOCAL_SET,
			    i+SKEW, dnp->side_names_key, &sn->dname,
			    &sn->mnum, NULL, ep)) == NULL) {
				/*
				 * It is possible that during the add of a
				 * host to have a 'missing' side as the side
				 * for this disk will be added later. So ignore
				 * the error. The 'missing' side will be added
				 * once the addhosts process has completed.
				 */
				if (mdissyserror(ep, ENOENT)) {
					mdclrerror(ep);
					Free(sn);
					continue;
				}

				if (sn->dname != NULL)
					Free(sn->dname);
				Free(sn);
				return (-1);
			}

			/* Add to the end of the linked list */
			assert(*sn_next == NULL);
			*sn_next = sn;
			sn_next = &sn->next;
		}
	}

	return (0);
}

static md_drive_desc *
rl_to_dd(
	mdsetname_t		*sp,
	md_replicalist_t	*rlp,
	md_error_t		*ep
)
{
	md_replicalist_t	*rl;
	md_replica_t		*r;
	md_drive_desc		*dd = NULL;
	md_drive_desc		*d;
	int			found;
	md_set_desc		*sd;
	daddr_t			nblks = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (NULL);

	/* find the smallest existing replica */
	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		r = rl->rl_repp;
		nblks = ((nblks == 0) ? r->r_nblk : min(r->r_nblk, nblks));
	}

	if (nblks <= 0)
		nblks = (MD_MNSET_DESC(sd)) ? MD_MN_DBSIZE : MD_DBSIZE;

	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		r = rl->rl_repp;

		found = 0;
		for (d = dd; d != NULL; d = d->dd_next) {
			if (strcmp(r->r_namep->drivenamep->cname,
			    d->dd_dnp->cname) == 0) {
				found = 1;
				dd->dd_dbcnt++;
				break;
			}
		}

		if (! found)
			(void) metadrivedesc_append(&dd, r->r_namep->drivenamep,
			    1, nblks, sd->sd_ctime, sd->sd_genid, MD_DR_OK);
	}

	return (dd);
}

/*
 * Exported Entry Points
 */

set_t
get_max_sets(md_error_t *ep)
{

	static set_t		max_sets = 0;

	if (max_sets == 0)
		if (metaioctl(MD_IOCGETNSET, &max_sets, ep, NULL) != 0)
			return (0);

	return (max_sets);
}

int
get_max_meds(md_error_t *ep)
{
	static int		max_meds = 0;

	if (max_meds == 0)
		if (metaioctl(MD_MED_GET_NMED, &max_meds, ep, NULL) != 0)
			return (0);

	return (max_meds);
}

side_t
getmyside(mdsetname_t *sp, md_error_t *ep)
{
	md_set_desc		*sd;
	char 			*node = NULL;
	side_t			sideno;

	if (sp->setno == 0)
		return (0);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (MD_SIDEWILD);

	node = mynode();

	assert(node != NULL);

	sideno = getnodeside(node, sd);

	if (sideno != MD_SIDEWILD)
		return (sideno);

	return (mddserror(ep, MDE_DS_HOSTNOSIDE, sp->setno, node, NULL, node));
}

/*
 * get set info from name
 */
md_set_record *
getsetbyname(char *setname, md_error_t *ep)
{
	md_set_record		*sr = NULL;
	md_mnset_record		*mnsr = NULL;
	char			*p;
	size_t			len;

	/* get set info from daemon */
	if (clnt_getset(mynode(), setname, MD_SET_BAD, &sr, ep) == -1)
		return (NULL);
	if (sr != NULL) {
		/*
		 * Returned record could be for a multi-node set or a
		 * non-multi-node set.
		 */
		if (MD_MNSET_REC(sr)) {
			/*
			 * Record is for a multi-node set.  Reissue call
			 * to get mnset information.  Need to free
			 * record as if a non-multi-node set record since
			 * that is what clnt_getset gave us.  If in
			 * the daemon, don't free since this is a pointer
			 * into the setrecords array.
			 */
			if (! md_in_daemon) {
				sr->sr_flags &= ~MD_SR_MN;
				free_sr(sr);
			}
			if (clnt_mngetset(mynode(), setname, MD_SET_BAD, &mnsr,
			    ep) == -1)
				return (NULL);
			if (mnsr != NULL)
				return ((struct md_set_record *)mnsr);
		} else {
			return (sr);
		}
	}

	/* no such set */
	len = strlen(setname) + 30;
	p = Malloc(len);
	(void) snprintf(p, len, "setname \"%s\"", setname);
	(void) mderror(ep, MDE_NO_SET, p);
	Free(p);
	return (NULL);
}

/*
 * get set info from number
 */
md_set_record *
getsetbynum(set_t setno, md_error_t *ep)
{
	md_set_record		*sr;
	md_mnset_record		*mnsr = NULL;
	char			buf[100];

	if (clnt_getset(mynode(), NULL, setno, &sr, ep) == -1)
		return (NULL);

	if (sr != NULL) {
		/*
		 * Record is for a multi-node set.  Reissue call
		 * to get mnset information.  Need to free
		 * record as if a non-multi-node set record since
		 * that is what clnt_getset gave us.  If in
		 * the daemon, don't free since this is a pointer
		 * into the setrecords array.
		 */
		if (MD_MNSET_REC(sr)) {
			/*
			 * Record is for a multi-node set.  Reissue call
			 * to get mnset information.
			 */
			if (! md_in_daemon) {
				sr->sr_flags &= ~MD_SR_MN;
				free_sr(sr);
			}
			if (clnt_mngetset(mynode(), NULL, setno, &mnsr,
			    ep) == -1)
				return (NULL);
			if (mnsr != NULL)
				return ((struct md_set_record *)mnsr);
		} else {
			return (sr);
		}
	}

	(void) sprintf(buf, "setno %u", setno);
	(void) mderror(ep, MDE_NO_SET, buf);
	return (NULL);
}

int
meta_check_drive_inuse(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	int		check_db,
	md_error_t	*ep
)
{
	mdnamelist_t	*nlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* get all underlying partitions */
	if (meta_getalldevs(sp, &nlp, check_db, ep) != 0)
		return (-1);

	/* search for drive */
	for (p = nlp; (p != NULL); p = p->next) {
		mdname_t	*np = p->namep;

		if (strcmp(dnp->cname, np->drivenamep->cname) == 0) {
			rval = (mddserror(ep, MDE_DS_DRIVEINUSE, sp->setno,
			    NULL, dnp->cname, sp->setname));
			break;
		}
	}

	/* cleanup, return success */
	metafreenamelist(nlp);
	return (rval);
}

/*
 * simple check for ownership
 */
int
meta_check_ownership(mdsetname_t *sp, md_error_t *ep)
{
	int			ownset;
	md_set_desc		*sd;
	md_drive_desc		*dd;
	md_replicalist_t	*rlp = NULL;
	md_error_t		xep = mdnullerror;

	if (metaislocalset(sp))
		return (0);

	ownset = own_set(sp, NULL, TRUE, ep);
	if (! mdisok(ep))
		return (-1);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST), ep);
	if (! mdisok(ep))
		return (-1);

	/* If we have no drive descriptors, check for no ownership */
	if (dd == NULL) {
		if (ownset == MD_SETOWNER_NONE)
			return (0);

		/* If ownership somehow has come to exist, we must clean up */

		if (metareplicalist(sp, (MD_BASICNAME_OK | PRINT_FAST), &rlp,
		    &xep) < 0)
			mdclrerror(&xep);

		if ((dd = rl_to_dd(sp, rlp, &xep)) == NULL)
			if (! mdisok(&xep))
				mdclrerror(&xep);

		if (!(MD_MNSET_DESC(sd)) && !MD_ATSET_DESC(sd)) {
			if (rel_own_bydd(sp, dd, TRUE, &xep))
				mdclrerror(&xep);
		}

		if (halt_set(sp, &xep))
			mdclrerror(&xep);

		metafreereplicalist(rlp);

		metafreedrivedesc(&dd);

		return (0);
	}

	metafreedrivedesc(&sd->sd_drvs);

	if (ownset == MD_SETOWNER_YES)
		return (0);

	return (mddserror(ep, MDE_DS_NOOWNER, sp->setno, NULL, NULL,
	    sp->setname));
}

/*
 * simple check for ownership
 */
int
meta_check_ownership_on_host(mdsetname_t *sp, char *hostname, md_error_t *ep)
{
	md_set_desc	*sd;
	md_drive_desc	*dd;
	int		bool;

	if (metaislocalset(sp))
		return (0);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (getnodeside(hostname, sd) == MD_SIDEWILD)
		return (mddserror(ep, MDE_DS_NODENOTINSET, sp->setno,
		    hostname, NULL, sp->setname));

	dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST), ep);
	if (! mdisok(ep))
		return (-1);

	if (clnt_ownset(hostname, sp, &bool, ep) == -1)
		return (-1);

	if (dd == NULL)
		return (0);

	metafreedrivedesc(&sd->sd_drvs);

	if (bool == TRUE)
		return (0);

	return (mddserror(ep, MDE_DS_NODEISNOTOWNER, sp->setno, hostname, NULL,
	    sp->setname));
}

/*
 * Function that determines if a node is in the multinode diskset
 * membership list.  Calling node passes in node to be checked and
 * the nodelist as returned from meta_read_nodelist.  This routine
 * anticipates being called many times using the same diskset membership
 * list which is why the alloc and free of the diskset membership list
 * is left to the calling routine.
 * Returns:
 *	1 - if a member
 *	0 - not a member
 */
int
meta_is_member(
	char				*node_name,
	md_mn_nodeid_t			node_id,
	mndiskset_membershiplist_t	*nl
)
{
	mndiskset_membershiplist_t	*nl2;
	int				flag_check_name;

	if (node_id != 0)
		flag_check_name = 0;
	else if (node_name != NULL)
		flag_check_name = 1;
	else
		return (0);

	nl2 = nl;
	while (nl2) {
		if (flag_check_name) {
			/* Compare given name against name in member list */
			if (strcmp(nl2->msl_node_name, node_name) == 0)
				break;
		} else {
			/* Compare given nodeid against nodeid in member list */
			if (nl2->msl_node_id == node_id)
				break;
		}
		nl2 = nl2->next;
	}
	/* No match found in member list */
	if (nl2 == NULL) {
		return (0);
	}
	/* Return 1 if node is in member list */
	return (1);
}

/*
 * meta_getnext_devinfo should go to the host that
 * has the device, to return the device name, driver name, minor num.
 * We can take the big cheat for now, since it is a requirement
 * that the device names and device numbers are the same, and
 * just get the info locally.
 *
 * This routine is very similar to meta_getnextside_devinfo except
 * that the specific side to be used is being passed in.
 *
 * Exit status:
 *	 0 - No more side info to return
 *	 1 - More side info's to return
 *	-1 - An error has been detected
 */
/*ARGSUSED*/
int
meta_getside_devinfo(
	mdsetname_t	*sp,		/* for this set */
	char		*bname,		/* local block name (myside) */
	side_t		sideno,		/* sideno */
	char		**ret_bname,	/* block device name of returned side */
	char		**ret_dname,	/* driver name of returned side */
	minor_t		*ret_mnum,	/* minor number of returned side */
	md_error_t	*ep
)
{
	mdname_t	*np;

	if (ret_bname != NULL)
		*ret_bname = NULL;
	if (ret_dname != NULL)
		*ret_dname = NULL;
	if (ret_mnum != NULL)
		*ret_mnum = NODEV32;


	if ((np = metaname(&sp, bname, LOGICAL_DEVICE, ep)) == NULL)
		return (-1);

/*
 * NOTE (future) - There will be more work here once devids are integrated
 * into disksets.  Then the side should be used to find the correct
 * host and the b/d names should be gotten from that host.
 */

	/*
	 * Return the side info.
	 */
	if (ret_bname != NULL)
		*ret_bname = Strdup(np->bname);

	if (ret_dname != NULL) {
		mdcinfo_t	*cinfo;

		if ((cinfo = metagetcinfo(np, ep)) == NULL)
			return (-1);

		*ret_dname = Strdup(cinfo->dname);
	}

	if (ret_mnum != NULL)
		*ret_mnum = meta_getminor(np->dev);

	return (1);
}

/*
 * Get the information on the device from the remote node using the devid
 * of the disk.
 *
 * Exit status:
 *	 0 - No more side info to return
 *	 1 - More side info's to return
 *	-1 - An error has been detected
 */
int
meta_getnextside_devinfo(
	mdsetname_t	*sp,		/* for this set */
	char		*bname,		/* local block name (myside) */
	side_t		*sideno,	/* previous sideno & returned sideno */
	char		**ret_bname,	/* block device name of returned side */
	char		**ret_dname,	/* driver name of returned side */
	minor_t		*ret_mnum,	/* minor number of returned side */
	md_error_t	*ep
)
{
	md_set_desc	*sd;
	int		i;
	mdname_t	*np;
	mddrivename_t	*dnp;
	char		*devidstr = NULL;
	int		devidstrlen;
	md_dev64_t	retdev = NODEV64;
	char		*ret_devname = NULL;
	char		*ret_blkdevname = NULL;
	char		*ret_driver = NULL;
	char		*nodename;
	int		fd;
	int		ret = -1;
	char		*minor_name = NULL;
	md_mnnode_desc	*nd;


	if (ret_bname != NULL)
		*ret_bname = NULL;
	if (ret_dname != NULL)
		*ret_dname = NULL;
	if (ret_mnum != NULL)
		*ret_mnum = NODEV32;

	if (metaislocalset(sp)) {
		/* no more sides - we are done */
		if (*sideno != MD_SIDEWILD)
			return (0);

		/* First time through -  set up return sideno */
		*sideno = 0;
	} else {

		/*
		 * Find the next sideno, starting after the one given.
		 */
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			if ((*sideno == MD_SIDEWILD) &&
			    (nd != (struct md_mnnode_desc *)NULL)) {
				*sideno = nd->nd_nodeid;
			} else {
				while (nd) {
					/*
					 * Found given sideno, now find
					 * next sideno, if there is one.
					 */
					if ((*sideno == nd->nd_nodeid) &&
					    (nd->nd_next !=
					    (struct md_mnnode_desc *)NULL)) {
						*sideno =
						    nd->nd_next->nd_nodeid;
						break;
					}
					nd = nd->nd_next;
				}
				if (nd == NULL) {
					return (0);
				}
			}
			if (*sideno == MD_SIDEWILD)
				return (0);
		} else {
			for (i = (*sideno)+1; i < MD_MAXSIDES; i++)
				/* Find next full slot */
				if (sd->sd_nodes[i][0] != '\0')
					break;

			/* No more sides - we are done */
			if (i == MD_MAXSIDES)
				return (0);

			/* Set up the return sideno */
			*sideno = i;
			nodename = (char *)sd->sd_nodes[i];
		}
	}

	/*
	 * Need to pass the node the devid of the disk and get it to
	 * send back the details of the disk from that side.
	 */
	if ((np = metaname(&sp, bname, UNKNOWN, ep)) == NULL)
		return (-1);

	dnp = np->drivenamep;

	/*
	 * By default, set up the parameters so that they are copied out.
	 */
	if (ret_bname != NULL)
		*ret_bname = Strdup(np->bname);

	if (ret_dname != NULL) {
		mdcinfo_t	*cinfo;

		if ((cinfo = metagetcinfo(np, ep)) == NULL)
			return (-1);

		*ret_dname = Strdup(cinfo->dname);
	}

	if (ret_mnum != NULL)
		*ret_mnum = meta_getminor(np->dev);

	/*
	 * Try some optimization. If this is the local set or the device
	 * is a metadevice then just copy the information. If the device
	 * does not have a devid (due to not having a minor name) then
	 * fall back to the pre-devid behaviour of copying the information
	 * on the device: this is okay because the sanity checks before this
	 * call would have found any issues with the device. If it's a
	 * multi-node diskset also just return ie. copy.
	 */
	if (metaislocalset(sp) || metaismeta(np) || (dnp->devid == NULL) ||
	    (MD_MNSET_DESC(sd)))
		return (1);

	if (np->minor_name == (char *)NULL) {
		/*
		 * Have to get the minor name then. The slice should exist
		 * on the disk because it will have already been repartitioned
		 * up prior to getting to this point.
		 */
		if ((fd = open(np->bname, (O_RDONLY|O_NDELAY), 0)) < 0) {
			(void) mdsyserror(ep, errno, np->bname);
			return (-1);
		}
		(void) devid_get_minor_name(fd, &minor_name);
		np->minor_name = Strdup(minor_name);
		devid_str_free(minor_name);
		(void) close(fd);
	}

	/* allocate extra space for "/" and NULL hence +2 */
	devidstrlen = strlen(dnp->devid) + strlen(np->minor_name) + 2;
	devidstr = (char *)Malloc(devidstrlen);

	/*
	 * As a minor name is supplied then the ret_devname will be
	 * appropriate to that minor_name and in this case it will be
	 * a block device ie /dev/dsk.
	 */
	(void) snprintf(devidstr, devidstrlen,
	    "%s/%s", dnp->devid, np->minor_name);

	ret = clnt_devinfo_by_devid(nodename, sp, devidstr, &retdev,
	    np->bname, &ret_devname, &ret_driver, ep);

	Free(devidstr);

	/*
	 * If the other side is not running device id in disksets,
	 * 'ret' is set to ENOTSUP in which case we fallback to
	 * the existing behaviour
	 */
	if (ret == ENOTSUP)
		return (1);
	else if (ret == -1)
		return (-1);

	/*
	 * ret_devname comes from the rpc call and is a
	 * raw device name. We need to make this into a
	 * block device via blkname for further processing.
	 * Unfortunately, when our device id isn't found in
	 * the system, the rpc call will return a " " in
	 * ret_devname in which case we need to fill that in
	 * as ret_blkname because blkname of " " returns NULL.
	 */
	if (ret_bname != NULL && ret_devname != NULL) {
		ret_blkdevname = blkname(ret_devname);
		if (ret_blkdevname == NULL)
			*ret_bname = Strdup(ret_devname);
		else
			*ret_bname = Strdup(ret_blkdevname);
	}

	if (ret_dname != NULL && ret_driver != NULL)
		*ret_dname = Strdup(ret_driver);

	if (ret_mnum != NULL)
		*ret_mnum = meta_getminor(retdev);

	return (1);
}

int
meta_is_drive_in_anyset(
	mddrivename_t	*dnp,
	mdsetname_t	**spp,
	int		bypass_daemon,
	md_error_t 	*ep
)
{
	set_t		setno;
	mdsetname_t	*this_sp;
	int		is_it;
	set_t		max_sets;

	if ((max_sets = get_max_sets(ep)) == 0)
		return (-1);

	assert(spp != NULL);
	*spp = NULL;

	for (setno = 1; setno < max_sets; setno++) {
		if (!bypass_daemon) {
			if ((this_sp = metasetnosetname(setno, ep)) == NULL) {
				if (mdismddberror(ep, MDE_DB_NODB)) {
					mdclrerror(ep);
					return (0);
				}
				if (mdiserror(ep, MDE_NO_SET)) {
					mdclrerror(ep);
					continue;
				}
				return (-1);
			}
		} else
			this_sp = metafakesetname(setno, NULL);

		if ((is_it = meta_is_drive_in_thisset(this_sp, dnp,
		    bypass_daemon, ep)) == -1) {
			if (mdiserror(ep, MDE_NO_SET)) {
				mdclrerror(ep);
				continue;
			}
			return (-1);
		}
		if (is_it) {
			*spp = this_sp;
			return (0);
		}
	}
	return (0);
}

int
meta_is_drive_in_thisset(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,
	int		bypass_daemon,
	md_error_t	*ep
)
{
	md_drive_desc	*dd, *p;

	if (bypass_daemon)
		dd = dr2drivedesc(sp, MD_SIDEWILD,
		    (MD_BASICNAME_OK | MD_BYPASS_DAEMON), ep);
	else
		dd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep);

	if (dd == NULL) {
		if (! mdisok(ep))
			return (-1);
		return (0);
	}


	for (p = dd; p != NULL; p = p->dd_next)
		if (strcmp(p->dd_dnp->cname, dnp->cname) == 0)
			return (1);
	return (0);
}

/*
 * Check to see if devid is in use in any diskset.
 * This is used in the case when a partial diskset is being imported
 * to make sure that the unvailable drive isn't already in use in an
 * already imported partial diskset.  Can't check on the cname since the
 * unavailable disk's cname is from the previous system and may collide
 * with a cname on this system.
 * Return values:
 *	1: devid has been found in a diskset
 *	0: devid not found in any diskset
 */
int
meta_is_devid_in_anyset(
	void		*devid,
	mdsetname_t	**spp,
	md_error_t 	*ep
)
{
	set_t		setno;
	mdsetname_t	*this_sp;
	int		is_it;
	set_t		max_sets;

	if ((max_sets = get_max_sets(ep)) == 0)
		return (-1);

	assert(spp != NULL);
	*spp = NULL;

	for (setno = 1; setno < max_sets; setno++) {
		if ((this_sp = metasetnosetname(setno, ep)) == NULL) {
			if (mdismddberror(ep, MDE_DB_NODB)) {
				mdclrerror(ep);
				return (0);
			}
			if (mdiserror(ep, MDE_NO_SET)) {
				mdclrerror(ep);
				continue;
			}
			return (-1);
		}

		if ((is_it = meta_is_devid_in_thisset(this_sp,
		    devid, ep)) == -1) {
			if (mdiserror(ep, MDE_NO_SET)) {
				mdclrerror(ep);
				continue;
			}
			return (-1);
		}
		if (is_it) {
			*spp = this_sp;
			return (0);
		}
	}
	return (0);
}

int
meta_is_devid_in_thisset(
	mdsetname_t	*sp,
	void		*devid,
	md_error_t	*ep
)
{
	md_drive_desc	*dd, *p;
	ddi_devid_t	dd_devid;

	dd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep);
	if (dd == NULL) {
		if (! mdisok(ep))
			return (-1);
		return (0);
	}

	for (p = dd; p != NULL; p = p->dd_next) {
		if (p->dd_dnp->devid == NULL)
			continue;
		(void) devid_str_decode(p->dd_dnp->devid,
		    &dd_devid, NULL);
		if (dd_devid == NULL)
			continue;
		if (devid_compare(devid, dd_devid) == 0) {
			devid_free(dd_devid);
			return (1);
		}
		devid_free(dd_devid);
	}
	return (0);
}

int
meta_set_balance(
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd, *curdd;
	daddr_t			dbsize;
	daddr_t			nblks;
	int			i;
	int			rval = 0;
	sigset_t		oldsigs;
	md_setkey_t		*cl_sk;
	md_error_t		xep = mdnullerror;
	md_mnnode_desc		*nd;
	int			suspend1_flag = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	dbsize = (MD_MNSET_DESC(sd)) ? MD_MN_DBSIZE : MD_DBSIZE;

	/* Make sure we own the set */
	if (meta_check_ownership(sp, ep) != 0)
		return (-1);

	/* END CHECK CODE */

	/*
	 * Get drive descriptors for the drives that are currently in the set.
	 */
	curdd = metaget_drivedesc(sp, MD_FULLNAME_ONLY, ep);

	if (! mdisok(ep))
		return (-1);

	/* Find the minimum replica size in use is or use the default */
	if ((nblks = meta_db_minreplica(sp, ep)) < 0)
		mdclrerror(ep);
	else
		dbsize = nblks;	/* adjust replica size */

	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	/*
	 * Lock the set on current set members.
	 * For MN diskset lock_set and SUSPEND are used to protect against
	 * other meta* commands running on the other nodes.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				rval = -1;
				goto out;
			}
			nd = nd->nd_next;
		}
		/*
		 * Lock out other meta* commands by suspending
		 * class 1 messages across the diskset.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename,
			    COMMDCTL_SUSPEND, sp, MD_MSG_CLASS1,
			    MD_MSCF_NO_FLAGS, ep)) {
				rval = -1;
				goto out;
			}
			suspend1_flag = 1;
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0') continue;

			if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
				rval = -1;
				goto out;
			}
		}
	}

	/* We are not adding or deleting any drives, just balancing */
	dd = NULL;

	/*
	 * Balance the DB's according to the list of existing drives and the
	 * list of added drives.
	 */
	if ((rval = meta_db_balance(sp, dd, curdd, dbsize, ep)) == -1)
		goto out;

out:
	/*
	 * Unlock diskset by resuming class 1 messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if (suspend1_flag) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				/*
				 * We are here because we failed to resume
				 * rpc.mdcommd.  However we potentially have
				 * an error from the previous call
				 * (meta_db_balance). If the previous call
				 * did fail,  we capture that error and
				 * generate a perror withthe string,
				 * "Unable to resume...".
				 * Setting rval to -1 ensures that in the
				 * next iteration of the loop, ep is not
				 * clobbered.
				 */
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd."));
			}
			nd = nd->nd_next;
		}
	}

	/* Unlock the set */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = -1;
			}
		}
	}

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	cl_set_setkey(NULL);

	metaflushsetname(sp);

	return (rval);
}

int
meta_set_destroy(
	mdsetname_t	*sp,
	int		lock_set,
	md_error_t	*ep
)
{
	int		i;
	med_rec_t	medr;
	md_set_desc	*sd;
	md_drive_desc	*dd, *p, *p1;
	mddrivename_t	*dnp;
	mdname_t	*np;
	mdnamelist_t	*nlp = NULL;
	int		num_users = 0;
	int		has_set;
	side_t		mysideno;
	sigset_t	oldsigs;
	md_error_t	xep = mdnullerror;
	md_setkey_t	*cl_sk;
	int		rval = 0;
	int		delete_end = 1;

	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, ep) < 0)
		return (-1);

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		if (! mdisok(ep))
			rval = -1;
		goto out;
	}

	/*
	 * meta_set_destroy should not be called for a MN diskset.
	 * This routine destroys a set without communicating this information
	 * to the other nodes which would lead to an inconsistency in
	 * the MN diskset.
	 */
	if (MD_MNSET_DESC(sd)) {
		rval = -1;
		goto out;
	}

	/* Continue if a traditional diskset */

	/*
	 * Check to see who has the set.  If we are not the last user of the
	 * set, we will not touch the replicas.
	 */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		has_set = nodehasset(sp, sd->sd_nodes[i], NHS_NST_EQ,
		    ep);

		if (has_set < 0) {
			mdclrerror(ep);
		} else
			num_users++;
	}

	if ((dd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep)) == NULL) {
		if (! mdisok(ep)) {
			rval = -1;
			goto out;
		}
	}

	if (setup_db_bydd(sp, dd, TRUE, ep) == -1) {
		rval = -1;
		goto out;
	}

	if (lock_set == TRUE) {
		/* Lock the set on our side */
		if (clnt_lock_set(mynode(), sp, ep)) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * A traditional diskset has no diskset stale information to send
	 * since there can only be one owner node at a time.
	 */
	if (snarf_set(sp, FALSE, ep))
		mdclrerror(ep);

	if (dd != NULL) {
		/*
		 * Make sure that no drives are in use as parts of metadrives
		 * or hot spare pools, this is one of the few error conditions
		 * that will stop this routine, unless the environment has
		 * META_DESTROY_SET_OK set, in which case, the operation will
		 * proceed.
		 */
		if (getenv("META_DESTROY_SET_OK") == NULL) {
			for (p = dd; p != NULL; p = p->dd_next) {
				dnp = p->dd_dnp;

				i = meta_check_drive_inuse(sp, dnp, FALSE, ep);
				if (i == -1) {
					/* need xep - wire calls clear error */
					i = metaget_setownership(sp, &xep);
					if (i == -1) {
						rval = -1;
						goto out;
					}

					mysideno = getmyside(sp, &xep);

					if (mysideno == MD_SIDEWILD) {
						rval = -1;
						goto out;
					}

					if (sd->sd_isown[mysideno] == FALSE)
						if (halt_set(sp, &xep)) {
							rval = -1;
							goto out;
						}

					rval = -1;
					goto out;
				}
			}
		}

		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Skip non local nodes */
			if (strcmp(mynode(), sd->sd_nodes[i]) != 0)
				continue;

			if (clnt_deldrvs(sd->sd_nodes[i], sp, dd, ep))
				mdclrerror(ep);
		}

		/*
		 * Go thru each drive and individually delete the replicas.
		 * This way we can ignore individual errors.
		 */
		for (p = dd; p != NULL; p = p->dd_next) {
			uint_t	rep_slice;

			dnp = p->dd_dnp;
			if ((meta_replicaslice(dnp, &rep_slice, ep) != 0) ||
			    (((np = metaslicename(dnp, rep_slice, ep))
			    == NULL) &&
			    ((np = metaslicename(dnp, MD_SLICE0, ep))
			    == NULL))) {
				rval = -1;
				goto out;
			}

			if ((np = metaslicename(dnp,
			    rep_slice, ep)) == NULL) {
				if ((np = metaslicename(dnp,
				    MD_SLICE0, ep)) == NULL) {
					rval = -1;
					goto out;
				}
				mdclrerror(ep);
			}

			/* Yes this is UGLY!!! */
			p1 = p->dd_next;
			p->dd_next = NULL;
			if (rel_own_bydd(sp, p, FALSE, ep))
				mdclrerror(ep);
			p->dd_next = p1;

			if (p->dd_dbcnt == 0)
				continue;

			/*
			 * Skip the replica removal if we are not the last user
			 */
			if (num_users != 1)
				continue;

			nlp = NULL;
			(void) metanamelist_append(&nlp, np);
			if (meta_db_detach(sp, nlp,
			    (MDFORCE_DS | MDFORCE_SET_LOCKED), NULL, ep))
				mdclrerror(ep);
			metafreenamelist(nlp);
		}
	}

	if (halt_set(sp, ep)) {
		rval = -1;
		goto out;
	}

	/* Setup the mediator record */
	(void) memset(&medr, '\0', sizeof (med_rec_t));
	medr.med_rec_mag = MED_REC_MAGIC;
	medr.med_rec_rev = MED_REC_REV;
	medr.med_rec_fl  = 0;
	medr.med_rec_sn  = sp->setno;
	(void) strcpy(medr.med_rec_snm, sp->setname);
	medr.med_rec_meds = sd->sd_med;	/* structure assigment */
	(void) memset(&medr.med_rec_data, '\0', sizeof (med_data_t));
	medr.med_rec_foff = 0;

	/*
	 * If we are the last remaining user, then remove the mediator hosts
	 */
	if (num_users == 1) {
		for (i = 0; i < MED_MAX_HOSTS; i++) {
			if (medr.med_rec_meds.n_lst[i].a_cnt != 0)
				SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE,
				    SVM_TAG_MEDIATOR, sp->setno, i);
			(void) memset(&medr.med_rec_meds.n_lst[i], '\0',
			    sizeof (md_h_t));
		}
		medr.med_rec_meds.n_cnt = 0;
	} else { 	/* Remove this host from the mediator node list. */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			/* Copy non local node */
			if (strcmp(mynode(), sd->sd_nodes[i]) != 0) {
				(void) strcpy(medr.med_rec_nodes[i],
				    sd->sd_nodes[i]);
				continue;
			}

			/* Clear local node */
			(void) memset(&medr.med_rec_nodes[i], '\0',
			    sizeof (md_node_nm_t));
		}
	}

	crcgen(&medr, &medr.med_rec_cks, sizeof (med_rec_t), NULL);

	/*
	 * If the client is part of a cluster put the DCS service
	 * into a deleteing state.
	 */
	if (sdssc_delete_begin(sp->setname) == SDSSC_ERROR) {
		if (metad_isautotakebyname(sp->setname)) {
			delete_end = 0;
		} else {
			mdclrerror(ep);
			goto out;
		}
	}

	/* Inform the mediator hosts of the new information */
	for (i = 0; i < MED_MAX_HOSTS; i++) {
		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;

		if (clnt_med_upd_rec(&sd->sd_med.n_lst[i], sp, &medr, ep))
			mdclrerror(ep);
	}

	/* Delete the set locally */
	for (i = 0; i < MD_MAXSIDES; i++) {
		/* Skip empty slots */
		if (sd->sd_nodes[i][0] == '\0')
			continue;

		/* Skip non local nodes */
		if (strcmp(mynode(), sd->sd_nodes[i]) != 0)
			continue;

		if (clnt_delset(sd->sd_nodes[i], sp, ep) == -1)
			mdclrerror(ep);
	}
	if (delete_end &&
	    sdssc_delete_end(sp->setname, SDSSC_COMMIT) == SDSSC_ERROR)
		rval = -1;

out:
	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0) {
		if (rval == 0)
			(void) mdstealerror(ep, &xep);
		rval = -1;
	}

	if (lock_set == TRUE) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		if (clnt_unlock_set(mynode(), cl_sk, &xep)) {
			if (rval == 0)
				(void) mdstealerror(ep, &xep);
			rval = -1;
		}
		cl_set_setkey(NULL);
	}

	metaflushsetname(sp);
	return (rval);
}

int
meta_set_purge(
	mdsetname_t	*sp,
	int		bypass_cluster,
	int		forceflg,
	md_error_t	*ep
)
{
	char		*thishost = mynode();
	md_set_desc	*sd;
	md_setkey_t	*cl_sk;
	md_error_t	xep = mdnullerror;
	int		rval = 0;
	int		i, num_hosts = 0;
	int		has_set = 0;
	int		max_node = 0;
	int		delete_end = 1;
	md_mnnode_desc	*nd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		/* unable to find set description */
		rval = 1;
		return (rval);
	}

	if (MD_MNSET_DESC(sd)) {
		/*
		 * Get a count of the hosts in the set and also lock the set
		 * on those hosts that know about it.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/*
			 * Only deal with those nodes that are members of
			 * the set (MD_MN_NODE_ALIVE) or the node on which
			 * the purge is being run. We must lock the set
			 * on the purging node because the delset call
			 * requires the lock to be set.
			 */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE) &&
			    nd->nd_nodeid != sd->sd_mn_mynode->nd_nodeid) {
				nd = nd->nd_next;
				continue;
			}
			has_set = nodehasset(sp, nd->nd_nodename,
			    NHS_NST_EQ, ep);

			/*
			 * The host is not aware of this set (has_set < 0) or
			 * the set does not match (has_set == 0). This check
			 * prevents the code getting confused by an apparent
			 * inconsistancy in the set's state, this is in the
			 * purge code so something is broken in any case and
			 * this is just trying to fix the brokeness.
			 */
			if (has_set <= 0) {
				mdclrerror(ep);
				nd->nd_flags |= MD_MN_NODE_NOSET;
			} else {
				num_hosts++;
				if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
					/*
					 * If the force flag is set then
					 * ignore any RPC failures because we
					 * are only really interested with
					 * the set on local node.
					 */
					if (forceflg && mdanyrpcerror(ep)) {
						mdclrerror(ep);
					} else {
						/*
						 * set max_node so that in the
						 * unlock code nodes in the
						 * set that have not been
						 * locked are not unlocked.
						 */
						max_node = nd->nd_nodeid;
						rval = 2;
						goto out1;
					}
				}

			}
			nd = nd->nd_next;
		}
		max_node = 0;
	} else {
		/*
		 * Get a count of the hosts in the set and also lock the set
		 * on those hosts that know about it.
		 */
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			has_set = nodehasset(sp, sd->sd_nodes[i],
			    NHS_NST_EQ, ep);

			/*
			 * The host is not aware of this set (has_set < 0) or
			 * the set does not match (has_set == 0). This check
			 * prevents the code getting confused by an apparent
			 * inconsistancy in the set's state, this is in the
			 * purge code so something is broken in any case and
			 * this is just trying to fix the brokeness.
			 */
			if (has_set <= 0) {
				mdclrerror(ep);
				/*
				 * set the node to NULL to prevent further
				 * requests to this unresponsive node.
				 */
				sd->sd_nodes[i][0] = '\0';
			} else {
				num_hosts++;
				if (clnt_lock_set(sd->sd_nodes[i], sp, ep)) {
					/*
					 * If the force flag is set then
					 * ignore any RPC failures because we
					 * are only really interested with
					 * the set on local node.
					 */
					if (forceflg && mdanyrpcerror(ep)) {
						mdclrerror(ep);
					} else {
						rval = 2;
						/*
						 * set max_node so that in the
						 * unlock code nodes in the
						 * set that have not been
						 * locked are not unlocked.
						 */
						max_node = i;
						goto out1;
					}
				}
			}
		}
		max_node = i;	/* now MD_MAXSIDES */
	}
	if (!bypass_cluster) {
		/*
		 * If there is only one host associated with the
		 * set then remove the set from the cluster.
		 */
		if (num_hosts == 1) {
			if (sdssc_delete_begin(sp->setname) == SDSSC_ERROR) {
				if (metad_isautotakebyname(sp->setname)) {
					delete_end = 0;
				} else {
					mdclrerror(ep);
					rval = 3;
					goto out1;
				}
			}
		}
	}

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (nd->nd_nodeid == sd->sd_mn_mynode->nd_nodeid) {
				/*
				 * This is the node on which the purge is
				 * being run. We do not care if it is
				 * alive or not, just want to get rid of
				 * the set.
				 */
				if (clnt_delset(nd->nd_nodename, sp,
				    ep) == -1) {
					md_perror(dgettext(TEXT_DOMAIN,
					    "delset"));
					if (!bypass_cluster && num_hosts == 1)
						(void) sdssc_delete_end(
						    sp->setname, SDSSC_CLEANUP);
					mdclrerror(ep);
					goto out1;
				}
				nd = nd->nd_next;
				continue;
			}

			/*
			 * Only contact those nodes that are members of
			 * the set.
			 */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/*
			 * Tell the remote node to remove this node
			 */
			if (clnt_delhosts(nd->nd_nodename, sp, 1, &thishost,
			    ep) == -1) {
				/*
				 * If we fail to delete ourselves
				 * from the remote host it does not
				 * really matter because the set is
				 * being "purged" from this node. The
				 * set can be purged from the other
				 * node at a later time.
				 */
				mdclrerror(ep);
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;
			if (strcmp(thishost, sd->sd_nodes[i]) != 0) {
				/*
				 * Tell the remote node to remove this node
				 */
				if (clnt_delhosts(sd->sd_nodes[i], sp, 1,
				    &thishost, ep) == -1) {
					/*
					 * If we fail to delete ourselves
					 * from the remote host it does not
					 * really matter because the set is
					 * being "purged" from this node. The
					 * set can be purged from the other
					 * node at a later time.
					 */
					mdclrerror(ep);
				}
				continue;
			}

			/* remove the set from this host */
			if (clnt_delset(sd->sd_nodes[i], sp, ep) == -1) {
				md_perror(dgettext(TEXT_DOMAIN, "delset"));
				if (!bypass_cluster && num_hosts == 1)
					(void) sdssc_delete_end(sp->setname,
					    SDSSC_CLEANUP);
				mdclrerror(ep);
				goto out1;
			}
		}
	}

	if (!bypass_cluster && num_hosts == 1) {
		if (delete_end && sdssc_delete_end(sp->setname, SDSSC_COMMIT) ==
		    SDSSC_ERROR) {
			rval = 4;
		}
	}

out1:

	cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/*
	 * Remove the set lock on those nodes that had the set locked
	 * max_node will either be MD_MAXSIDES or array index of the last
	 * node contacted (or rather failed to contact) for traditional
	 * diskset.  For a MN diskset, max_node is the node_id of the node
	 * that failed the lock.
	 */
	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (nd->nd_nodeid == max_node)
				break;
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
				if (forceflg && mdanyrpcerror(&xep)) {
					mdclrerror(&xep);
					nd = nd->nd_next;
					continue;
				}
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = 5;
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < max_node; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (clnt_unlock_set(sd->sd_nodes[i], cl_sk, &xep)) {
				if (forceflg && mdanyrpcerror(&xep)) {
					mdclrerror(&xep);
					continue;
				}
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				rval = 5;
			}
		}
	}

	cl_set_setkey(NULL);

	return (rval);
}

int
meta_set_query(
	mdsetname_t		*sp,
	mddb_dtag_lst_t		**dtlpp,
	md_error_t		*ep
)
{
	mddb_dtag_get_parm_t	dtgp;

	(void) memset(&dtgp, '\0', sizeof (mddb_dtag_get_parm_t));
	dtgp.dtgp_setno = sp->setno;

	/*CONSTCOND*/
	while (1) {
		if (metaioctl(MD_MED_GET_TAG, &dtgp, &dtgp.dtgp_mde, NULL) != 0)
			if (! mdismddberror(&dtgp.dtgp_mde, MDE_DB_NOTAG) ||
			    *dtlpp == NULL)
				return (mdstealerror(ep, &dtgp.dtgp_mde));
			else
				break;

		/*
		 * Run to the end of the list
		 */
		for (/* void */; (*dtlpp != NULL); dtlpp = &(*dtlpp)->dtl_nx)
			/* void */;

		*dtlpp = Zalloc(sizeof (mddb_dtag_lst_t));

		(void) memmove(&(*dtlpp)->dtl_dt, &dtgp.dtgp_dt,
		    sizeof (mddb_dtag_t));

		dtgp.dtgp_dt.dt_id++;
	}
	return (0);
}

/*
 * return drivename get by key
 */
mddrivename_t *
metadrivename_withdrkey(
	mdsetname_t	*sp,
	side_t		sideno,
	mdkey_t		key,
	int		flags,
	md_error_t	*ep
)
{
	char		*nm;
	mdname_t	*np;
	mddrivename_t	*dnp;
	ddi_devid_t	devidp;
	md_set_desc	*sd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		return (NULL);
	}

	/*
	 * Get the devid associated with the key.
	 *
	 * If a devid was returned, it MUST be valid even in
	 * the case where a device id has been "updated". The
	 * "update" of the device id may have occured due to
	 * a firmware upgrade.
	 */
	if ((devidp = meta_getdidbykey(MD_LOCAL_SET, sideno+SKEW, key, ep))
	    != NULL) {
		/*
		 * Look for the correct dnp using the devid for comparison.
		 */
		dnp = meta_getdnp_bydevid(sp, sideno, devidp, key, ep);
		free(devidp);

		/* dnp could be NULL if the devid could not be decoded. */
		if (dnp == NULL) {
			return (NULL);
		}
		dnp->side_names_key = key;
	} else {
		/*
		 * We didn't get a devid. We'll try for a dnp using the
		 * name. If we have a MN diskset or if the dnp is a did
		 * device, we're done because then we don't have devids.
		 * Otherwise we'll try to set the devid
		 * and get the dnp via devid again.
		 * We also need to clear the ep structure. When the
		 * above call to meta_getdidbykey returned a null, it
		 * also put an error code into ep. In this case, the null
		 * return is actually OK and any errors can be ignored. The
		 * reason it is OK is because this could be a MN set or
		 * we could  be running without devids (ex cluster).
		 */
		mdclrerror(ep);

		if ((nm = meta_getnmbykey(MD_LOCAL_SET, sideno, key,
		    ep)) == NULL)
			return (NULL);
		/* get device name */
		if (flags & PRINT_FAST) {
			if ((np = metaname_fast(&sp, nm,
			    LOGICAL_DEVICE, ep)) == NULL) {
				Free(nm);
				return (NULL);
			}
		} else {
			if ((np = metaname(&sp, nm, LOGICAL_DEVICE,
			    ep)) == NULL) {
				Free(nm);
				return (NULL);
			}
		}
		Free(nm);
		/* make sure it's OK */
		if ((! (flags & MD_BASICNAME_OK)) && (metachkcomp(np,
		    ep) != 0))
			return (NULL);

		/* get drivename */
		dnp = np->drivenamep;
		dnp->side_names_key = key;
		/*
		 * Skip the devid set/check for the following cases:
		 * 1) If MN diskset, there are no devid's
		 * 2) if dnp is did device
		 * The device id is disabled for did device due to the
		 * lack of minor name support in the did driver. The following
		 * devid code path can set and propagate the error and
		 * eventually prevent did disks from being added to the
		 * diskset under SunCluster systems
		 *
		 * Note that this code can be called through rpc.mdcommd.
		 * sdssc_version cannot be used because the library won't
		 * be bound.
		 */
		if ((strncmp(dnp->rname, "/dev/did/", strlen("/dev/did/"))
		    == 0) || (MD_MNSET_DESC(sd)))
			goto out;

		/*
		 * It is okay if replica is not in devid mode
		 */
		if (mdissyserror(ep, MDDB_F_NODEVID)) {
			mdclrerror(ep);
			goto out;
		}

		/*
		 * We're not MN or did devices but
		 * devid is missing so this means that we have
		 * just upgraded from a configuration where
		 * devid's were not used so try to add in
		 * the devid and requery. If the devid still isn't there,
		 * that's OK. dnp->devid will be null as it is in any
		 * configuration with no devids.
		 */
		if (meta_setdid(MD_LOCAL_SET, sideno + SKEW, key, ep) < 0)
			return (NULL);
		if ((devidp = (ddi_devid_t)meta_getdidbykey(MD_LOCAL_SET,
		    sideno+SKEW, key, ep)) != NULL) {
			/*
			 * Found a devid so look for the dnp using the
			 * devid as the search mechanism.
			 */
			dnp = meta_getdnp_bydevid(sp, sideno, devidp, key, ep);
			free(devidp);
			if (dnp == NULL) {
				return (NULL);
			}
			dnp->side_names_key = key;
		}
	}



out:
	if (flags & MD_BYPASS_DAEMON)
		return (dnp);

	if (get_sidenmlist(sp, dnp, ep))
		return (NULL);

	/* return success */
	return (dnp);
}

void
metafreedrivedesc(md_drive_desc **dd)
{
	md_drive_desc	*p, *next = NULL;

	for (p = *dd; p != NULL; p = next) {
		next = p->dd_next;
		Free(p);
	}
	*dd = NULL;
}

md_drive_desc *
metaget_drivedesc(
	mdsetname_t	*sp,
	int		flags,
	md_error_t	*ep
)
{
	side_t		sideno = MD_SIDEWILD;

	assert(! (flags & MD_BYPASS_DAEMON));

	if ((sideno = getmyside(sp, ep)) == MD_SIDEWILD)
		return (NULL);

	return (metaget_drivedesc_sideno(sp, sideno, flags, ep));
}

md_drive_desc *
metaget_drivedesc_fromnamelist(
	mdsetname_t	*sp,
	mdnamelist_t	*nlp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	mdnamelist_t		*p;
	md_drive_desc		*dd = NULL;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (NULL);

	for (p = nlp; p != NULL; p = p->next)
		(void) metadrivedesc_append(&dd, p->namep->drivenamep, 0, 0,
		    sd->sd_ctime, sd->sd_genid, MD_DR_ADD);

	return (dd);
}

md_drive_desc *
metaget_drivedesc_sideno(
	mdsetname_t *sp,
	side_t sideno,
	int flags,
	md_error_t *ep
)
{
	md_set_desc	*sd = NULL;

	assert(! (flags & MD_BYPASS_DAEMON));

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (NULL);

	if (sd->sd_drvs)
		return (sd->sd_drvs);

	if ((sd->sd_drvs = dr2drivedesc(sp, sideno, flags, ep)) == NULL)
		return (NULL);

	return (sd->sd_drvs);
}

int
metaget_setownership(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc	*sd;
	int		bool;
	int		i;
	md_mnnode_desc	*nd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* If node isn't alive, can't own diskset */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd->nd_flags &= ~MD_MN_NODE_OWN;
				nd = nd->nd_next;
				continue;
			}
			/*
			 * If can't communicate with rpc.metad, then mark
			 * this node as not an owner.  That node may
			 * in fact, be an owner, but without rpc.metad running
			 * that node can't do much.
			 */
			if (clnt_ownset(nd->nd_nodename, sp, &bool, ep) == -1) {
				nd->nd_flags &= ~MD_MN_NODE_OWN;
			} else if (bool == TRUE) {
				nd->nd_flags |= MD_MN_NODE_OWN;
			} else {
				nd->nd_flags &= ~MD_MN_NODE_OWN;
			}
			nd = nd->nd_next;
		}
		return (0);
	}

	/* Rest of code handles traditional disksets */

	for (i = 0; i < MD_MAXSIDES; i++)
		sd->sd_isown[i] = 0;

	if (clnt_ownset(mynode(), sp, &bool, ep) == -1)
		return (-1);

	if (bool == TRUE)
		sd->sd_isown[getmyside(sp, ep)] = 1;

	return (0);
}

char *
mynode(void)
{
	static struct utsname	myuname;
	static int		done = 0;

	if (! done) {
		if (uname(&myuname) == -1) {
			md_perror(dgettext(TEXT_DOMAIN, "uname"));
			assert(0);
		}
		done = 1;
	}
	return (myuname.nodename);
}

int
strinlst(char *str, int cnt, char **lst)
{
	int i;

	for (i = 0; i < cnt; i++)
		if (strcmp(lst[i], str) == 0)
			return (TRUE);

	return (FALSE);
}

/*
 * meta_get_reserved_names
 *  returns an mdnamelist_t of reserved slices
 *  reserved slices are those that are used but don't necessarily
 *  show up as metadevices (ex. reserved slice for db in sets, logs)
 */

/*ARGSUSED*/
int
meta_get_reserved_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep)
{
	int		 count		= 0;
	mdname_t	*np		= NULL;
	mdnamelist_t	*transnlp	= NULL;
	mdnamelist_t	**tailpp 	= nlpp;
	mdnamelist_t	*nlp;
	md_drive_desc	*dd, *di;

	if (metaislocalset(sp))
		goto out;

	if (!(dd = metaget_drivedesc(sp, MD_BASICNAME_OK, ep)) && !mdisok(ep)) {
		count = -1;
		goto out;
	}

	/* db in for sets on reserved slice */
	for (di = dd; di && count >= 0; di = di->dd_next) {
		uint_t	rep_slice;

		/*
		 * Add the name struct to the end of the
		 * namelist but keep a pointer to the last
		 * element so that we don't incur the overhead
		 * of traversing the list each time
		 */
		if (di->dd_dnp &&
		    (meta_replicaslice(di->dd_dnp, &rep_slice, ep) == 0) &&
		    (np = metaslicename(di->dd_dnp, rep_slice, ep)) &&
		    (tailpp = meta_namelist_append_wrapper(tailpp, np)))
			count++;
		else
			count = -1;
	}

	/* now find logs */
	if (meta_get_trans_names(sp, &transnlp, 0, ep) < 0) {
		count = -1;
		goto out;
	}

	for (nlp = transnlp; (nlp != NULL); nlp = nlp->next) {
		mdname_t	*transnp = nlp->namep;
		md_trans_t	*transp;

		if ((transp = meta_get_trans(sp, transnp, ep)) == NULL) {
			count = -1;
			goto out;
		}
		if (transp->lognamep) {
			/*
			 * Add the name struct to the end of the
			 * namelist but keep a pointer to the last
			 * element so that we don't incur the overhead
			 * of traversing the list each time
			 */
			tailpp = meta_namelist_append_wrapper(
			    tailpp, transp->lognamep);
		}
	}
out:
	metafreenamelist(transnlp);
	return (count);
}

/*
 * Entry point to join a node to MultiNode diskset.
 *
 * Validate host in diskset.
 *	- Should be in membership list from API
 *	- Should not already be joined into diskset.
 *	- Set must have drives
 * Assume valid configuration is stored in the set/drive/node records
 * in the local mddb since no node or drive can be added to the MNset
 * unless all drives and nodes are available.  Reconfig steps will
 * resync all ALIVE nodes in case of panic in critical areas.
 *
 * Lock down the set.
 * Verify host is a member of this diskset.
 * If drives exist in the configuration, load the mddbs.
 * Set this node to active by notifying master if one exists.
 * If this is the first node active in the diskset, this node
 * 	becomes the master.
 * Unlock the set.
 *
 * Mirror Resync:
 * If this node is the last node to join the set and clustering
 * isn't running, then start the 'metasync -r' type resync
 * on all mirrors in this diskset.
 * If clustering is running, this resync operation will
 * be handled by the reconfig steps and should NOT
 * be handled during a join operation.
 *
 * There are multiple return values in order to assist
 * the join operation of all sets in the metaset command.
 *
 * Return values:
 *	0  - Node successfully joined to set.
 *	-1 - Join attempted but failed
 *		- any failure from libmeta calls
 *		- node not in the member list
 *	-2 - Join not attempted since
 *		- this set had no drives in set
 *		- this node already joined to set
 *		- set is not a multinode set
 *	-3 - Node joined to STALE set.
 */
extern int
meta_set_join(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd;
	md_mnnode_desc		*nd, *nd2, my_nd;
	int			rval = 0;
	md_setkey_t		*cl_sk;
	md_error_t		xep = mdnullerror;
	md_error_t		ep_snarf = mdnullerror;
	int			master_flag = 0;
	md_mnset_record		*mas_mnsr = NULL;
	int			clear_nr_flags = 0;
	md_mnnode_record	*nr;
	int			stale_set = 0;
	int			rb_flags = 0;
	int			stale_bool = FALSE;
	int			suspendall_flag = 0;
	int			suspend1_flag = 0;
	sigset_t		oldsigs;
	int			send_reinit = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		return (-1);
	}

	/* Must be a multinode diskset */
	if (!MD_MNSET_DESC(sd)) {
		(void) mderror(ep, MDE_NOT_MN, sp->setname);
		return (-2);
	}

	/* Verify that the node is ALIVE (i.e. is in the API membership list) */
	if (!(sd->sd_mn_mynode->nd_flags & MD_MN_NODE_ALIVE)) {
		(void) mddserror(ep, MDE_DS_NOTINMEMBERLIST, sp->setno,
		    sd->sd_mn_mynode->nd_nodename, NULL, sp->setname);
		return (-1);
	}

	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	/*
	 * Lock the set on current set members.
	 * For MN diskset lock_set and SUSPEND are used to protect against
	 * other meta* commands running on the other nodes.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
			rval = -1;
			goto out;
		}
		nd = nd->nd_next;
	}

	/*
	 * Lock out other meta* commands by suspending
	 * class 1 messages across the diskset.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
		    sp, MD_MSG_CLASS1, MD_MSCF_NO_FLAGS, ep)) {
			rval = -1;
			goto out;
		}
		suspend1_flag = 1;
		nd = nd->nd_next;
	}

	/*
	 * Verify that this host is a member (in the host list) of the set.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (strcmp(mynode(), nd->nd_nodename) == 0) {
			break;
		}
		nd = nd->nd_next;
	}
	if (!nd) {
		(void) mddserror(ep, MDE_DS_NODENOTINSET, sp->setno,
		    sd->sd_mn_mynode->nd_nodename, NULL,
		    sp->setname);
		rval = -1;
		goto out;
	}

	/*
	 * Need to return failure if host is already 'joined'
	 * into the set.  This is done so that if later the user
	 * issues a command to join all sets and a failure is
	 * encountered - that the resulting cleanup effort
	 * (withdrawing from all sets that were joined
	 * during that command) won't withdraw from this set.
	 */
	if (nd->nd_flags & MD_MN_NODE_OWN) {
		rval = -2;
		goto out2;
	}

	/*
	 * Call metaget_setownership that calls each node in diskset and
	 * marks in set descriptor if node is an owner of the set or not.
	 * metaget_setownership checks to see if a node is an owner by
	 * checking to see if that node's kernel has the mddb loaded.
	 * If a node had panic'd during a reconfig or an
	 * add/delete/join/withdraw operation, the other nodes' node
	 * records may not reflect the current state of the diskset,
	 * so calling metaget_setownership is the safest thing to do.
	 */
	if (metaget_setownership(sp, ep) == -1) {
		rval = -1;
		goto out;
	}

	/* If first active member of diskset, become the master. */
	nd = sd->sd_nodelist;
	while (nd) {
		if (nd->nd_flags & MD_MN_NODE_OWN)
			break;
		nd = nd->nd_next;
	}
	if (nd == NULL)
		master_flag = 1;

	/*
	 * If not first active member of diskset, then get the
	 * master information from a node that is already joined
	 * and set the master information for this node.  Be sure
	 * that this node (the already joined node) has its own
	 * join flag set.  If not, then this diskset isn't currently
	 * consistent and shouldn't allow a node to join.  This diskset
	 * inconsistency should only occur when a node has panic'd in
	 * the set while doing a metaset operation and the sysadmin is
	 * attempting to join a node into the set.  This inconsistency
	 * will be fixed during a reconfig cycle which should be occurring
	 * soon since a node panic'd.
	 *
	 * If unable to get this information from an owning node, then
	 * this diskset isn't currently consistent and shouldn't
	 * allow a node to join.
	 */
	if (!master_flag) {
		/* get master information from an owner (joined) node */
		if (clnt_mngetset(nd->nd_nodename, sp->setname,
		    sp->setno, &mas_mnsr, ep) == -1) {
			rval = -1;
			goto out;
		}

		/* Verify that owner (joined) node has its own JOIN flag set */
		nr = mas_mnsr->sr_nodechain;
		while (nr) {
			if ((nd->nd_nodeid == nr->nr_nodeid) &&
			    ((nr->nr_flags & MD_MN_NODE_OWN) == NULL)) {
				(void) mddserror(ep, MDE_DS_NODENOSET,
				    sp->setno, nd->nd_nodename, NULL,
				    nd->nd_nodename);
				free_sr((md_set_record *)mas_mnsr);
				rval = -1;
				goto out;
			}
			nr = nr->nr_next;
		}

		/*
		 * Does master have set marked as STALE?
		 * If so, need to pass this down to kernel when
		 * this node snarfs the set.
		 */
		if (clnt_mn_is_stale(nd->nd_nodename, sp,
		    &stale_bool, ep) == -1) {
			rval = -1;
			goto out;
		}

		/* set master information in my rpc.metad's set record */
		if (clnt_mnsetmaster(mynode(), sp, mas_mnsr->sr_master_nodenm,
		    mas_mnsr->sr_master_nodeid, ep)) {
			free_sr((md_set_record *)mas_mnsr);
			rval = -1;
			goto out;
		}

		/* set master information in my cached set desc */
		(void) strcpy(sd->sd_mn_master_nodenm,
		    mas_mnsr->sr_master_nodenm);
		sd->sd_mn_master_nodeid = mas_mnsr->sr_master_nodeid;
		nd2 = sd->sd_nodelist;
		while (nd2) {
			if (nd2->nd_nodeid == mas_mnsr->sr_master_nodeid) {
				sd->sd_mn_masternode = nd2;
				break;
			}
			nd2 = nd2->nd_next;
		}
		free_sr((md_set_record *)mas_mnsr);

		/*
		 * Set the node flags in mynode's rpc.metad node records for
		 * the nodes that are in the diskset.  Can use my sd
		 * since earlier call to metaget_setownership set the
		 * owner flags based on whether that node had snarfed
		 * the MN diskset mddb.  Reconfig steps guarantee that
		 * return of metaget_setownership will match the owning
		 * node's owner list except in the case where a node
		 * has just panic'd and in this case, a reconfig will
		 * be starting immediately and the owner lists will
		 * be sync'd up by the reconfig.
		 *
		 * Flag of SET means to take no action except to
		 * set the node flags as given in the nodelist linked list.
		 */
		if (clnt_upd_nr_flags(mynode(), sp, sd->sd_nodelist,
		    MD_NR_SET, NULL, ep)) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * Read in the mddb if there are drives in the set.
	 */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		/* No drives in list */
		if (! mdisok(ep)) {
			rval = -1;
			goto out;
		}
		rval = -2;
		goto out;
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Start by suspending rpc.mdcommd (which drains it of all messages),
	 * then change the nodelist followed by a reinit and resume.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}

		if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND, sp,
		    MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, ep)) {
			rval = -1;
			goto out;
		}
		suspendall_flag = 1;
		nd = nd->nd_next;
	}

	/* Set master in my set record in rpc.metad */
	if (master_flag) {
		if (clnt_mnsetmaster(mynode(), sp,
		    sd->sd_mn_mynode->nd_nodename,
		    sd->sd_mn_mynode->nd_nodeid, ep)) {
			rval = -1;
			goto out;
		}
	}
	/*
	 * Causes mddbs to be loaded into the kernel.
	 * Set the force flag so that replica locations can be
	 * loaded into the kernel even if a mediator node was
	 * unavailable.  This allows a node to join an MO
	 * diskset when there are sufficient replicas available,
	 * but a mediator node in unavailable.
	 */
	if (setup_db_bydd(sp, dd, TRUE, ep) == -1) {
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Host not able to start diskset."));
		rval = -1;
		goto out;
	}

	if (! mdisok(ep)) {
		rval = -1;
		goto out;
	}

	/*
	 * Set rollback flags to 1 so that halt_set is called if a failure
	 * is seen after this point.  If snarf_set fails, still need to
	 * call halt_set to cleanup the diskset.
	 */
	rb_flags = 1;

	/* Starts the set */
	if (snarf_set(sp, stale_bool, ep) != 0) {
		if (mdismddberror(ep, MDE_DB_STALE)) {
			/*
			 * Don't fail join, STALE means that set has
			 * < 50% mddbs.
			 */
			(void) mdstealerror(&ep_snarf, ep);
			stale_set = 1;
		} else if (mdisok(ep)) {
			/* If snarf failed, but no error was set - set it */
			(void) mdmddberror(ep, MDE_DB_NOTNOW, (minor_t)NODEV64,
			    sp->setno, 0, NULL);
				rval = -1;
				goto out;
		} else if (!(mdismddberror(ep, MDE_DB_ACCOK))) {
			/*
			 * Don't fail join if ACCOK; ACCOK means that mediator
			 * provided extra vote.
			 */
			rval = -1;
			goto out;
		}
	}

	/* Did set really get snarfed? */
	if (own_set(sp, NULL, TRUE, ep) == MD_SETOWNER_NO) {
		if (mdisok(ep)) {
			/* If snarf failed, but no error was set - set it */
			(void) mdmddberror(ep, MDE_DB_NOTNOW, (minor_t)NODEV64,
			    sp->setno, 0, NULL);
		}
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Host not able to start diskset."));
		rval = -1;
		goto out;
	}

	/* Change to nodelist so need to send reinit to rpc.mdcommd */
	send_reinit = 1;

	/* If first node to enter set, setup master and clear change log */
	if (master_flag) {
		/* Set master in my locally cached set descriptor */
		(void) strcpy(sd->sd_mn_master_nodenm,
		    sd->sd_mn_mynode->nd_nodename);
		sd->sd_mn_master_nodeid = sd->sd_mn_mynode->nd_nodeid;
		sd->sd_mn_am_i_master = 1;

		/*
		 * If first node to join set, then clear out change log
		 * entries.  Change log entries are only needed when a
		 * change of master is occurring in a diskset that has
		 * multiple owners.   Since this node is the first owner
		 * of the diskset, clear the entries.
		 *
		 * Only do this if we are in a single node non-SC3.x
		 * situation.
		 */
		if (meta_mn_singlenode() &&
		    mdmn_reset_changelog(sp, ep,  MDMN_CLF_RESETLOG) != 0) {
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Unable to reset changelog."));
			rval = -1;
			goto out;
		}
	}

	/* Set my locally cached flag */
	sd->sd_mn_mynode->nd_flags |= MD_MN_NODE_OWN;

	/*
	 * Set this node's own flag on all joined nodes in the set
	 * (including my node).
	 */
	clear_nr_flags = 1;

	my_nd = *(sd->sd_mn_mynode);
	my_nd.nd_next = NULL;
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_upd_nr_flags(nd->nd_nodename, sp, &my_nd,
		    MD_NR_JOIN, NULL, ep)) {
			rval = -1;
			goto out;
		}
		nd = nd->nd_next;
	}

out:
	if (rval != NULL) {
		/*
		 * If rollback flag is 1, then node was joined to set.
		 * Since an error occurred, withdraw node from set in
		 * order to rollback to before command was run.
		 * Need to preserve ep so that calling function can
		 * get error information.
		 */
		if (rb_flags == 1) {
			if (halt_set(sp, &xep)) {
				mdclrerror(&xep);
			}
		}

		/*
		 * If error, reset master to INVALID.
		 * Ignore error since (next) first node to successfully join
		 * will set master on all nodes.
		 */
		(void) clnt_mnsetmaster(mynode(), sp, "",
		    MD_MN_INVALID_NID, &xep);
		mdclrerror(&xep);
		/* Reset master in my locally cached set descriptor */
		sd->sd_mn_master_nodeid = MD_MN_INVALID_NID;
		sd->sd_mn_am_i_master = 0;

		/*
		 * If nr flags set on other nodes, reset them.
		 */
		if (clear_nr_flags) {
			nd = sd->sd_nodelist;
			while (nd) {
				if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
					nd = nd->nd_next;
					continue;
				}
				(void) clnt_upd_nr_flags(nd->nd_nodename, sp,
				    &my_nd, MD_NR_WITHDRAW, NULL, &xep);
				mdclrerror(&xep);
				nd = nd->nd_next;
			}
			/* Reset my locally cached flag */
			sd->sd_mn_mynode->nd_flags &= ~MD_MN_NODE_OWN;
		}
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (send_reinit) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				/*
				 * We are here because we failed to resume
				 * rpc.mdcommd.  However we potentially have
				 * an error from the previous call
				 * If the previous call did fail,  we capture
				 * that error and generate a perror with
				 * the string, "Unable to resume...".
				 * Setting rval to -1 ensures that in the
				 * next iteration of the loop, ep is not
				 * clobbered.
				 */
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd."));
			}
			nd = nd->nd_next;
		}

	}

out2:
	/*
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				/*
				 * We are here because we failed to resume
				 * rpc.mdcommd.  However we potentially have
				 * an error from the previous call
				 * If the previous call did fail,  we capture
				 * that error and generate a perror with
				 * the string, "Unable to resume...".
				 * Setting rval to -1 ensures that in the
				 * next iteration of the loop, ep is not
				 * clobbered.
				 */
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd."));
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/*
	 * Unlock set.  This flushes the caches on the servers.
	 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
			if (rval == 0)
				(void) mdstealerror(ep, &xep);
			else
				mdclrerror(&xep);
			rval = -1;
		}
		nd = nd->nd_next;
	}

	/*
	 * If this node is the last to join the diskset and clustering isn't
	 * running, then resync the mirrors in the diskset. We have to wait
	 * until all nodes are joined so that the status gets propagated to
	 * all of the members of the set.
	 * Ignore any error from the resync as the join function shouldn't fail
	 * because the mirror resync had a problem.
	 *
	 * Don't start resync if set is stale.
	 */
	if ((rval == 0) && (sdssc_bind_library() != SDSSC_OKAY) &&
	    (stale_set != 1)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_OWN))
				break;
			nd = nd->nd_next;
		}
		/*
		 * nd set to NULL means that we have no nodes in the set that
		 * haven't joined. In this case we start the resync.
		 */
		if (nd == NULL) {
			(void) meta_mirror_resync_all(sp, 0, &xep);
			mdclrerror(&xep);
		}
	}

	/* Update ABR state for all soft partitions */
	(void) meta_sp_update_abr(sp, &xep);
	mdclrerror(&xep);

	/*
	 * call metaflushsetnames to reset local cache for master and
	 * node information.
	 */
	metaflushsetname(sp);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	/*
	 * If no error and stale_set is set, then set ep back
	 * to ep from snarf_set call and return -3.  If another error
	 * occurred and rval is not 0, then that error would have
	 * caused the node to be withdrawn from the set and would
	 * have set ep to that error information.
	 */
	if ((rval == 0) && (stale_set)) {
		(void) mdstealerror(ep, &ep_snarf);
		return (-3);
	}

	return (rval);
}

/*
 * Entry point to withdraw a node from MultiNode diskset.
 *
 * Validate host in diskset.
 *	- Should be joined into diskset.
 * Assume valid configuration is stored in the set/drive/node records
 * in the local mddb since no node or drive can be added to the MNset
 * unless all drives and nodes are available.  Reconfig steps will
 * resync all ALIVE nodes in case of panic in critical areas.
 *
 * Lock down the set.
 * Verify that drives exist in configuration.
 * Verify host is a member of this diskset.
 * Verify host is an owner of the diskset (host is joined to diskset).
 * Only allow withdrawal of master node if master node is the only joined
 * in the diskset.
 * Halt the diskset on this node.
 * Reset Master on this node.
 * Updated node flags that this node with withdrawn.
 * Unlock the set.
 *
 * Return values:
 *	0  - Node successfully withdrew from set.
 *	-1 - Withdrawal attempted but failed
 *		- any failure from libmeta calls
 *		- node not in the member list
 *	-2 - Withdrawal not attempted since
 *		- this set had no drives in set
 *		- this node not joined to set
 *		- set is not a multinode set
 */
extern int
meta_set_withdraw(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	md_drive_desc		*dd = 0;
	md_mnnode_desc		*nd, my_nd;
	int			rval = 0;
	md_setkey_t		*cl_sk;
	md_error_t		xep = mdnullerror;
	int			set_halted = 0;
	int			suspendall_flag = 0;
	int			suspend1_flag = 0;
	bool_t			stale_bool = FALSE;
	mddb_config_t		c;
	int			node_id_list[1];
	sigset_t		oldsigs;
	int			send_reinit = 0;

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		return (-1);
	}

	/* Must be a multinode diskset */
	if (!MD_MNSET_DESC(sd)) {
		(void) mderror(ep, MDE_NOT_MN, sp->setname);
		return (-1);
	}

	/* Make sure we are blocking all signals */
	if (procsigs(TRUE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	/*
	 * Lock the set on current set members.
	 * For MN diskset lock_set and SUSPEND are used to protect against
	 * other meta* commands running on the other nodes.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
			rval = -1;
			goto out;
		}
		nd = nd->nd_next;
	}
	/*
	 * Lock out other meta* commands by suspending
	 * class 1 messages across the diskset.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
		    sp, MD_MSG_CLASS1, MD_MSCF_NO_FLAGS, ep)) {
			rval = -1;
			goto out;
		}
		suspend1_flag = 1;
		nd = nd->nd_next;
	}

	/* Get list of drives - needed in case of failure */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		/* Error getting drives in list */
		if (! mdisok(ep)) {
			rval = -1;
			goto out2;
		}
		/* no drives in list */
		rval = -2;
		goto out2;
	}

	/*
	 * Verify that this host is a member (in the host list) of the set.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (strcmp(mynode(), nd->nd_nodename) == 0) {
			break;
		}
		nd = nd->nd_next;
	}
	if (!nd) {
		(void) mddserror(ep, MDE_DS_NODENOTINSET, sp->setno,
		    sd->sd_mn_mynode->nd_nodename, NULL,
		    sp->setname);
		rval = -1;
		goto out2;
	}

	/*
	 * Call metaget_setownership that calls each node in diskset and
	 * marks in set descriptor if node is an owner of the set or not.
	 * metaget_setownership checks to see if a node is an owner by
	 * checking to see if that node's kernel has the mddb loaded.
	 * If a node had panic'd during a reconfig or an
	 * add/delete/join/withdraw operation, the other nodes' node
	 * records may not reflect the current state of the diskset,
	 * so calling metaget_setownership is the safest thing to do.
	 */
	if (metaget_setownership(sp, ep) == -1) {
		rval = -1;
		goto out2;
	}

	/*
	 * Verify that this node is joined
	 * to diskset (i.e. is an owner of the diskset).
	 */
	if (!(sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
		rval = -2;
		goto out2;
	}

	/*
	 * For a MN diskset, only withdraw master if it is
	 * the only joined node.
	 */
	if (sd->sd_mn_master_nodeid == sd->sd_mn_mynode->nd_nodeid) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip my node since checking for other owners */
			if (nd->nd_nodeid == sd->sd_mn_master_nodeid) {
				nd = nd->nd_next;
				continue;
			}
			/* If another owner node if found, error */
			if (nd->nd_flags & MD_MN_NODE_OWN) {
				(void) mddserror(ep, MDE_DS_WITHDRAWMASTER,
				    sp->setno,
				    sd->sd_mn_mynode->nd_nodename, NULL,
				    sp->setname);
				rval = -1;
				goto out2;
			}
			nd = nd->nd_next;
		}
	}

	/*
	 * Is current set STALE?
	 */
	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;
	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c.c_mde);
		rval = -1;
		goto out;
	}
	if (c.c_flags & MDDB_C_STALE) {
		stale_bool = TRUE;
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Start by suspending rpc.mdcommd (which drains it of all messages),
	 * then change the nodelist followed by a reinit and resume.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}

		if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_SUSPEND,
		    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, ep)) {
			rval = -1;
			goto out;
		}
		suspendall_flag = 1;
		nd = nd->nd_next;
	}

	/*
	 * Withdraw the set - halt set.
	 * This will fail if any I/O is occuring to any metadevice which
	 * includes a resync to a mirror metadevice.
	 */
	set_halted = 1;
	if (halt_set(sp, ep)) {
		/* Was set actually halted? */
		if (own_set(sp, NULL, TRUE, ep) == MD_SETOWNER_YES) {
			set_halted = 0;
		}
		rval = -1;
		goto out;
	}

	/* Change to nodelist so need to send reinit to rpc.mdcommd */
	send_reinit = 1;

	/* Reset master on withdrawn node */
	if (clnt_mnsetmaster(sd->sd_mn_mynode->nd_nodename, sp, "",
	    MD_MN_INVALID_NID, ep)) {
		rval = -1;
		goto out;
	}

	/* Mark my node as withdrawn and send to other nodes */
	nd = sd->sd_nodelist;
	my_nd = *(sd->sd_mn_mynode);	/* structure copy */
	my_nd.nd_next = NULL;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_upd_nr_flags(nd->nd_nodename, sp, &my_nd,
		    MD_NR_WITHDRAW, NULL, ep)) {
			rval = -1;
			goto out;
		}
		nd = nd->nd_next;
	}

	/*
	 * If withdrawn node is a mirror owner, reset mirror owner
	 * to NULL.  If an error occurs, print a warning and continue.
	 * Don't fail metaset because of mirror owner reset problem since
	 * next node to grab mirror will resolve this issue.
	 * Before next node grabs mirrors, metaset will show the withdrawn
	 * node as owner which is why an attempt to reset the mirror owner
	 * is made.
	 */
	node_id_list[0] = sd->sd_mn_mynode->nd_nodeid;	/* Setup my nodeid */
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_reset_mirror_owner(nd->nd_nodename, sp,
		    1, &node_id_list[0], &xep) == 01) {
			mde_perror(&xep, dgettext(TEXT_DOMAIN,
			    "Unable to reset mirror owner on node %s"),
			    nd->nd_nodename);
			mdclrerror(&xep);
		}
		nd = nd->nd_next;
	}

out:
	if (rval == -1) {
		/* Rejoin node - Mark node as joined and send to other nodes */
		nd = sd->sd_nodelist;
		my_nd = *(sd->sd_mn_mynode);	/* structure copy */
		my_nd.nd_next = NULL;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_upd_nr_flags(nd->nd_nodename, sp, &my_nd,
			    MD_NR_JOIN, NULL, &xep)) {
				mdclrerror(&xep);
			}
			nd = nd->nd_next;
		}

		/* Set master on withdrawn node */
		if (clnt_mnsetmaster(sd->sd_mn_mynode->nd_nodename, sp,
		    sd->sd_mn_master_nodenm,
		    sd->sd_mn_master_nodeid, &xep)) {
			mdclrerror(&xep);
		}

		/* Join set if halt_set had succeeded */
		if (set_halted) {
			/*
			 * Causes mddbs to be loaded into the kernel.
			 * Set the force flag so that replica locations can be
			 * loaded into the kernel even if a mediator node was
			 * unavailable.  This allows a node to join an MO
			 * diskset when there are sufficient replicas available,
			 * but a mediator node in unavailable.
			 */
			if (setup_db_bydd(sp, dd, TRUE, &xep) == -1) {
				mdclrerror(&xep);
			}
			/* If set previously stale - make it so at re-join */
			if (snarf_set(sp, stale_bool, &xep) != 0) {
				mdclrerror(&xep);
				(void) halt_set(sp, &xep);
				mdclrerror(&xep);
			}
		}
	}

	/*
	 * Notify rpc.mdcommd on all nodes of a nodelist change.
	 * Send reinit command to mdcommd which forces it to get
	 * fresh set description.
	 */
	if (send_reinit) {
		/* Send reinit */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Class is ignored for REINIT */
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_REINIT,
			    sp, NULL, MD_MSCF_NO_FLAGS, &xep)) {
				/*
				 * We are here because we failed to resume
				 * rpc.mdcommd.  However we potentially have
				 * an error from the previous call.
				 * If the previous call did fail,  we
				 * capture that error and generate a perror
				 * withthe string,  "Unable to resume...".
				 * Setting rval to -1 ensures that in the
				 * next iteration of the loop, ep is not
				 * clobbered.
				 */
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reinit rpc.mdcommd."));
			}
			nd = nd->nd_next;
		}
	}

out2:
	/*
	 * Unlock diskset by resuming messages across the diskset.
	 * Just resume all classes so that resume is the same whether
	 * just one class was locked or all classes were locked.
	 */
	if ((suspend1_flag) || (suspendall_flag)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mdcommdctl(nd->nd_nodename, COMMDCTL_RESUME,
			    sp, MD_MSG_CLASS0, MD_MSCF_NO_FLAGS, &xep)) {
				/*
				 * We are here because we failed to resume
				 * rpc.mdcommd.  However we potentially have
				 * an error from the previous call
				 * If the previous call did fail,  we capture
				 * that error and generate a perror with
				 * the string, "Unable to resume...".
				 * Setting rval to -1 ensures that in the
				 * next iteration of the loop, ep is not
				 * clobbered.
				 */
				if (rval == 0)
					(void) mdstealerror(ep, &xep);
				else
					mdclrerror(&xep);
				rval = -1;
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume rpc.mdcommd."));
			}
			nd = nd->nd_next;
		}
		meta_ping_mnset(sp->setno);
	}

	/*
	 * Unlock set.  This flushes the caches on the servers.
	 */
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
			if (rval == 0)
				(void) mdstealerror(ep, &xep);
			else
				mdclrerror(&xep);
			rval = -1;
		}
		nd = nd->nd_next;
	}

	/*
	 * call metaflushsetnames to reset local cache for master and
	 * node information.
	 */
	metaflushsetname(sp);

	/* release signals back to what they were on entry */
	if (procsigs(FALSE, &oldsigs, &xep) < 0)
		mdclrerror(&xep);

	return (rval);

}

/*
 * Update nodelist with cluster member information.
 * A node not in the member list will be marked
 * as not ALIVE and not OWN.
 * A node in the member list will be marked ALIVE, but
 * the OWN bit will not be changed.
 *
 * If mynode isn't in the membership list, fail causing
 * another reconfig cycle to be started since a non-member
 * node shouldn't be taking part in the reconfig cycle.
 *
 * Return values:
 *	0 - No problem.
 *	1 - Any failure including RPC failure to my node.
 */
int
meta_reconfig_update_nodelist(
	mdsetname_t			*sp,
	mndiskset_membershiplist_t	*nl,
	md_set_desc			*sd,
	md_error_t			*ep
)
{
	mndiskset_membershiplist_t	*nl2;
	md_mnnode_desc			*nd;
	md_error_t			xep = mdnullerror;
	int				rval = 0;

	/*
	 * Walk through nodelist, checking to see if each
	 * node is in the member list.
	 * If node is not a member, reset ALIVE and OWN node flag.
	 * If node is a member, set ALIVE.
	 * If mynode's OWN flag gets reset, then halt the diskset on this node.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		nl2 = nl;
		while (nl2) {
			/* If node is in member list, set ALIVE */
			if (nl2->msl_node_id == nd->nd_nodeid) {
				nd->nd_flags |= MD_MN_NODE_ALIVE;
				break;
			} else {
				nl2 = nl2->next;
			}
			/* node is not in member list, mark !ALIVE and !OWN */
			if (nl2 == NULL) {
				/* If node is mynode, then halt set if needed */
				if (strcmp(mynode(), nd->nd_nodename) == 0) {
					/*
					 * This shouldn't happen, but just
					 * in case...  Any node not in the
					 * membership list should be dead and
					 * not running reconfig step1.
					 */
					if (nd->nd_flags & MD_MN_NODE_OWN) {
						if (halt_set(sp, &xep)) {
							mde_perror(&xep, "");
							mdclrerror(&xep);
						}
					}
					/*
					 * Return failure since this node
					 * (mynode) is not in the membership
					 * list, but process the rest of the
					 * nodelist first so that rpc.metad
					 * can be updated with the latest
					 * membership information.
					 */
					(void) mddserror(ep,
					    MDE_DS_NOTINMEMBERLIST,
					    sp->setno, nd->nd_nodename, NULL,
					    sp->setname);
					rval = 1;
				}
				nd->nd_flags &= ~MD_MN_NODE_ALIVE;
				nd->nd_flags &= ~MD_MN_NODE_OWN;
			}
		}
		nd = nd->nd_next;
	}

	/* Send this information to rpc.metad */
	if (clnt_upd_nr_flags(mynode(), sp, sd->sd_nodelist,
	    MD_NR_SET,  MNSET_IN_RECONFIG, &xep)) {
		/* Return failure if can't send node flags to rpc.metad */
		if (rval == 0) {
			(void) mdstealerror(ep, &xep);
			rval = 1;
		}
	}
	return (rval);
}

/*
 * Choose master determines the master for a diskset.
 * Each node determines the master on its own and
 * adds this information to its local rpc.metad nodelist
 * and also sends it to the kernel.
 *
 * Nodelist in set descriptor (sd) is sorted in
 * monotonically increasing sequence of nodeid.
 *
 * Return values:
 *	0 - No problem.
 *	205 - There was an RPC problem to another node.
 *	-1 - There was an error.  This could be an RPC error to my node.
 *		This is a catastrophic failure causing node to panic.
 */
int
meta_reconfig_choose_master_for_set(
	mdsetname_t	*sp,
	md_set_desc	*sd,
	md_error_t	*ep
)
{
	int			is_owner;
	md_mnset_record		*mnsr = NULL;
	int			lowest_alive_nodeid = 0;
	uint_t			master_nodeid;
	md_mnnode_desc		*nd, *nd2;
	md_mnnode_record	*nr;
	md_drive_desc		*dd;
	md_setkey_t		*cl_sk;
	int			rval = 0;
	md_error_t		xep = mdnullerror;
	mddb_setflags_config_t	sf;

	/*
	 * Is current node joined to diskset?
	 * Don't trust flags, really check to see if mddb is snarfed.
	 */
	if (s_ownset(sp->setno, ep) == MD_SETOWNER_YES) {
		/*
		 * If a node is joined to the diskset, this node checks
		 * to see if the current master of the diskset is valid and
		 * is still in the membership list (ALIVE) and is
		 * still joined (OWN).  Need to verify if master is
		 * really joined - don't trust the flags.  (Can trust
		 * ALIVE since set during earlier part of reconfig cycle.)
		 * If the current master is valid, still in the membership
		 * list and joined, then master is not changed on this node.
		 * Just return.
		 *
		 * Verify that nodeid is valid before accessing masternode.
		 */
		if ((sd->sd_mn_master_nodeid != MD_MN_INVALID_NID) &&
		    (sd->sd_mn_masternode->nd_flags & MD_MN_NODE_ALIVE)) {
			if (clnt_ownset(sd->sd_mn_master_nodenm, sp,
			    &is_owner, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    sd->sd_mn_master_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			} else {
				if (is_owner == TRUE) {

					meta_mc_log(MC_LOG5, dgettext(
					    TEXT_DOMAIN, "Set %s previous "
					    "master chosen %s (%d): %s"),
					    sp->setname,
					    sd->sd_mn_master_nodenm,
					    sd->sd_mn_master_nodeid,
					    meta_print_hrtime(gethrtime() -
					    start_time));

					/* Previous master is ok - done */
					return (0);
				}
			}
		}

		/*
		 * If current master is no longer in the membership list or
		 * is no longer joined, then this node uses the following
		 * algorithm:
		 * - node calls RPC routine clnt_ownset to get latest
		 *	information on which nodes are owners of diskset.
		 * 	clnt_ownset checks on each node to see if its kernel
		 *	has that diskset snarfed.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_ownset(nd->nd_nodename, sp,
			    &is_owner, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}

			/*
			 * Set owner flag for each node based on whether
			 * that node really has a diskset mddb snarfed in
			 * or not.
			 */
			if (is_owner == TRUE)
				nd->nd_flags |= MD_MN_NODE_OWN;
			else
				nd->nd_flags &= ~MD_MN_NODE_OWN;

			nd = nd->nd_next;
		}

		/*
		 * - node walks through nodelist looking for nodes that are
		 *	owners of the diskset that are in the membership list.
		 * - for each owner, node calls RPC routine clnt_getset to
		 *	 see if that node has its node record set to OK.
		 * - If so, master is chosen to be this owner node.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Don't consider a node that isn't an owner */
			if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
				nd = nd->nd_next;
				continue;
			}

			/* Does node has its own node record set to OK? */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (nd->nd_nodeid == nr->nr_nodeid) {
					if (nr->nr_flags & MD_MN_NODE_OK) {
						/* Found a master */
						free_sr(
						    (md_set_record *)mnsr);
						goto found_master;
					}
				}
				nr = nr->nr_next;
			}
			free_sr((md_set_record *)mnsr);
			nd = nd->nd_next;
		}

		/*
		 * - If no owner node has its own node record on its own node
		 *	set to OK, then this node checks all of the non-owner
		 * 	nodes that are in the membership list.
		 * - for each non-owner, node calls RPC routine clnt_getset to
		 *	 see if that node has its node record set to OK.
		 * - If set doesn't exist, don't choose node for master.
		 * - If so, master is chosen to be this non-owner node.
		 *
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Only checking non-owner nodes this time around */
			if (nd->nd_flags & MD_MN_NODE_OWN) {
				nd = nd->nd_next;
				continue;
			}

			/* Does node has its own node record set to OK? */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, ep) == -1) {
				/*
				 * If set doesn't exist on non-owner node,
				 * don't consider this node for master.
				 */
				if (mdiserror(ep, MDE_NO_SET)) {
					nd = nd->nd_next;
					continue;
				} else if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					/* RPC failure to another node */
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (nd->nd_nodeid == nr->nr_nodeid) {
					if (nr->nr_flags & MD_MN_NODE_OK) {
						/* Found a master */
						free_sr(
						    (md_set_record *)mnsr);
						goto found_master;
					}
				}
				nr = nr->nr_next;
			}
			free_sr((md_set_record *)mnsr);
			nd = nd->nd_next;
		}

		/*
		 * - If no node can be found that has its own node record on
		 *	its node to be set to OK, then all alive nodes
		 * 	were in the process of being added to or deleted
		 *	from set.  Each alive node will remove all
		 *	information pertaining to this set from its node.
		 *
		 * If all nodes in set are ALIVE, then call sdssc end routines
		 * since set was truly being initially created or destroyed.
		 */
		goto delete_set;
	} else {

		/*
		 * If node is not joined to diskset, then this
		 * node uses the following algorithm:
		 * - If unjoined node doesn't have a node record for itself,
		 *	just delete the diskset since diskset was in the
		 *	process of being created.
		 * - node needs to find master of diskset before
		 *	reconfig cycle, if a master existed.
		 * - node calls RPC routine clnt_ownset to get latest
		 * 	information on which nodes are owners of diskset.
		 *	clnt_ownset checks on each node to see if its
		 *	kernel has that diskset snarfed.
		 */

		/*
		 * Is my node in the set description?
		 * If not, delete the set from this node.
		 * sr2setdesc sets sd_mn_mynode pointer to the node
		 * descriptor for this node if there was a node
		 * record for this node.
		 *
		 */
		if (sd->sd_mn_mynode == NULL) {
			goto delete_set;
		}

		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_ownset(nd->nd_nodename, sp,
			    &is_owner, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}

			/*
			 * Set owner flag for each node based on whether
			 * that node really has a diskset mddb snarfed in
			 * or not.
			 */
			if (is_owner == TRUE)
				nd->nd_flags |= MD_MN_NODE_OWN;
			else
				nd->nd_flags &= ~MD_MN_NODE_OWN;

			nd = nd->nd_next;
		}

		/*
		 * - node walks through nodelist looking for nodes that
		 *	are owners of the diskset that are in
		 *	the membership list.
		 * - for each owner, node calls RPC routine clnt_getset to
		 *	see if that node has a master set and to get the
		 *	diskset description.
		 * - If the owner node has a set description that doesn't
		 *	include the non-joined node in the nodelist, this node
		 *	removes its set description of that diskset
		 *	(i.e. removes the set from its local mddbs).  This is
		 *	handling the case of when a node was removed from a
		 *	diskset while it was not in the cluster membership
		 *	list.
		 * - If that node has a master set and the master is in the
		 *	membership list and is an owner, then either this was
		 *	the master from before the reconfig cycle or this
		 *	node has already chosen a new master - either way,
		 *	the master value is valid as long as it is in the
		 *	membership list and is an owner
		 * - master is chosen to be owner node's master
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Don't consider a node that isn't an owner */
			if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
				nd = nd->nd_next;
				continue;
			}

			/* Get owner node's set record */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}

			/* Is this node in the owner node's set record */
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (sd->sd_mn_mynode->nd_nodeid ==
				    nr->nr_nodeid) {
					break;
				}
				nr = nr->nr_next;
			}
			if (nr == NULL) {
				/* my node not found - delete set */
				free_sr((md_set_record *)mnsr);
				goto delete_set;
			}

			/* Is owner's node's master valid? */
			master_nodeid = mnsr->sr_master_nodeid;
			free_sr((md_set_record *)mnsr);
			if (master_nodeid == MD_MN_INVALID_NID) {
				nd = nd->nd_next;
				continue;
			}

			nd2 = sd->sd_nodelist;
			while (nd2) {
				if ((nd2->nd_nodeid == master_nodeid) &&
				    (nd2->nd_flags & MD_MN_NODE_ALIVE) &&
				    (nd2->nd_flags & MD_MN_NODE_OWN)) {
						nd = nd2;
						goto found_master;
				}
				nd2 = nd2->nd_next;
			}
			nd = nd->nd_next;
		}

		/*
		 * - If no owner node has a valid master, then follow
		 * 	algorithm of when a node is joined to the diskset.
		 * - node walks through nodelist looking for nodes that are
		 *	owners of the diskset that are in the membership list.
		 * - for each owner, node calls RPC routine clnt_getset to
		 *	 see if that node has its node record set to OK.
		 * - If so, master is chosen to be this owner node.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			/* Don't consider a node that isn't an owner */
			if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
				nd = nd->nd_next;
				continue;
			}

			/* Does node has its own node record set to OK? */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, ep) == -1) {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (nd->nd_nodeid == nr->nr_nodeid) {
					if (nr->nr_flags & MD_MN_NODE_OK) {
						/* Found a master */
						free_sr(
						    (md_set_record *)mnsr);
						goto found_master;
					}
				}
				nr = nr->nr_next;
			}
			free_sr((md_set_record *)mnsr);
			nd = nd->nd_next;
		}

		/*
		 * - If no owner node has its own node record on its own node
		 *	set to OK, then this node checks all of the non-owner
		 *	nodes that are in the membership list.
		 * - for each non-owner, node calls RPC routine clnt_getset to
		 *	see if that node has its node record set to OK.
		 * - If set doesn't exist, don't choose node for master.
		 * - If this node doesn't exist in the nodelist on any of the
		 *	non-owner nodes, this node removes its set description
		 *	of that diskset (i.e. removes the set from its local
		 *	mddbs). This is handling the case of when a node was
		 *	removed from a diskset while it was not in the
		 *	cluster membership list.
		 * - If non-owner node has its node record set to OK and if
		 *	this node hasn't removed this diskset (step directly
		 *	before this one), then the master is chosen to be this
		 *	non-owner node.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Don't consider node that isn't in member list */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd->nd_flags |= MD_MN_NODE_DEL;
				nd = nd->nd_next;
				continue;
			}

			/* Don't consider owner nodes since none are OK */
			if (nd->nd_flags & MD_MN_NODE_OWN) {
				nd->nd_flags |= MD_MN_NODE_DEL;
				nd = nd->nd_next;
				continue;
			}

			/*
			 * Don't need to get nodelist from my node since
			 * this is where sd_nodelist was obtained.
			 */
			if (sd->sd_mn_mynode->nd_nodeid == nd->nd_nodeid) {
				nd = nd->nd_next;
				continue;
			}

			/*
			 * If node has already been decided against for
			 * master, then skip it.
			 */
			if (nd->nd_flags & MD_MN_NODE_DEL) {
				nd = nd->nd_next;
				continue;
			}

			/*
			 * Does node in my nodelist have its own node
			 * record marked OK on its node?  And does node
			 * in my nodelist exist on all other nodes?
			 * Don't want to choose a node for master unless
			 * that node is marked OK on its own node and that
			 * node exists on all other alive nodes.
			 *
			 * This is guarding against the case when several
			 * nodes are down and one of the downed nodes is
			 * deleted from the diskset.  When the down nodes
			 * are rebooted into the cluster, you don't want
			 * any node to pick the deleted node as the master.
			 */
			if (clnt_mngetset(nd->nd_nodename, sp->setname,
			    MD_SET_BAD, &mnsr, ep) == -1) {
				/*
				 * If set doesn't exist on non-owner node,
				 * don't consider this node for master.
				 */
				if (mdiserror(ep, MDE_NO_SET)) {
					nd->nd_flags |= MD_MN_NODE_DEL;
					nd = nd->nd_next;
					continue;
				} else if (mdanyrpcerror(ep)) {
					/* RPC failure to another node */
					return (205);
				} else {
					/* Any other failure */
					return (-1);
				}
			}
			/*
			 * Is my node in the nodelist gotten from the other
			 * node?  If not, then remove the set from my node
			 * since set was deleted from my node while my node
			 * was out of the cluster.
			 */
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (sd->sd_mn_mynode->nd_nodeid ==
				    nr->nr_nodeid) {
					break;
				}
				nr = nr->nr_next;
			}
			if (nr == NULL) {
				/* my node not found - delete set */
				free_sr((md_set_record *)mnsr);
				goto delete_set;
			}

			/* Is node being checked marked OK on its own node? */
			nr = mnsr->sr_nodechain;
			while (nr) {
				if (nd->nd_nodeid == nr->nr_nodeid) {
					if (!(nr->nr_flags & MD_MN_NODE_OK)) {
						nd->nd_flags |= MD_MN_NODE_DEL;
					}
					break;
				}
				nr = nr->nr_next;
			}
			/*
			 * If node being checked doesn't exist on its
			 * own node - don't choose it as master.
			 */
			if (nr == NULL) {
				nd->nd_flags |= MD_MN_NODE_DEL;
			}

			/*
			 * Check every node in my node's nodelist against
			 * the nodelist gotten from the other node.
			 * If a node in my node's nodelist is not found in the
			 * other node's nodelist, then set the DEL flag.
			 */
			nd2 = sd->sd_nodelist;
			while (nd2) {
				nr = mnsr->sr_nodechain;
				while (nr) {
					if (nd2->nd_nodeid == nr->nr_nodeid) {
						break;
					}
					nr = nr->nr_next;
				}
				/* nd2 not found in other node's nodelist */
				if (nr == NULL) {
					nd2->nd_flags |= MD_MN_NODE_DEL;
				}
				nd2 = nd2->nd_next;
			}

			free_sr((md_set_record *)mnsr);
			nd = nd->nd_next;
		}

		/*
		 * Rescan list look for node that has not been marked DEL.
		 * First node found is the master.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			if (!(nd->nd_flags & MD_MN_NODE_DEL)) {
				break;
			}
			nd = nd->nd_next;
			continue;
		}
		if (nd) {
			/* Found a master */
			goto found_master;
		}

		/*
		 * - If no node can be found that has its own node record on
		 *	its node to be set to OK, then all alive nodes
		 * 	were in the process of being added to or deleted
		 *	from set.  Each alive node will remove all
		 *	information pertaining to this set from its node.
		 *
		 * If all nodes in set are ALIVE, then call sdssc end routines
		 * since set was truly being initially created or destroyed.
		 */
		goto delete_set;
	}

found_master:
	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Set %s master chosen %s (%d): %s"),
	    sp->setname, nd->nd_nodename, nd->nd_nodeid,
	    meta_print_hrtime(gethrtime() - start_time));

	if (clnt_lock_set(mynode(), sp, ep) == -1) {
		return (-1);
	}

	cl_sk = cl_get_setkey(sp->setno, sp->setname);

	if (clnt_mnsetmaster(mynode(), sp,
	    nd->nd_nodename, nd->nd_nodeid, ep)) {
		rval = -1;
	} else if (sd->sd_mn_mynode->nd_nodeid == nd->nd_nodeid) {
		/* If this node is new master, set flag in this node's kernel */
		(void) memset(&sf, 0, sizeof (sf));
		sf.sf_setno = sp->setno;
		sf.sf_setflags = MD_SET_MN_NEWMAS_RC;
		/* Use magic to help protect ioctl against attack. */
		sf.sf_magic = MDDB_SETFLAGS_MAGIC;
		sf.sf_flags = MDDB_NM_SET;

		meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
		    "Setting new master flag for set %s: %s"),
		    sp->setname, meta_print_hrtime(gethrtime() - start_time));

		/*
		 * Fail reconfig cycle if ioctl fails since it is critical
		 * to set new master flag.
		 */
		if (metaioctl(MD_MN_SET_SETFLAGS, &sf, &sf.sf_mde,
		    NULL) != NULL) {
			(void) mdstealerror(ep, &sf.sf_mde);
			rval = -1;
		}
	}

	if (clnt_unlock_set(mynode(), cl_sk, &xep) == -1) {
		if (rval == 0) {
			(void) mdstealerror(ep, &xep);
			rval = -1;
		}
	}

	cl_set_setkey(NULL);

	metaflushsetname(sp);

	return (rval);

delete_set:
	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Master not chosen, deleting set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	/*
	 * Remove all set information from this node:
	 *	- node records for this set
	 *	- drive records for this set
	 *	- set record for this set
	 * (Only do this on this node since each node
	 * will do it for its own local mddb.)
	 *
	 * If all nodes in set are ALIVE, then
	 * the lowest numbered ALIVE nodeid in set
	 * (irregardless of whether an owner node or not) will
	 * call the DCS service to cleanup for create/delete of set.
	 *   sdssc_create_end(cleanup) if set was being created or
	 *   sdssc_delete_end(cleanup) if set was being deleted.
	 * A node record with flag ADD denotes a set being
	 * created.  A node record with flag DEL denotes a
	 * set being deleted.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		/* Found a node that isn't alive */
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE))
			break;

		/* Is my node the lowest numbered ALIVE node? */
		if (nd->nd_nodeid < sd->sd_mn_mynode->nd_nodeid) {
			break;
		}
		nd = nd->nd_next;
	}
	if (nd == NULL) {
		/* All nodes ALIVE and this is the lowest nodeid */
		lowest_alive_nodeid = 1;
	}

	if (clnt_lock_set(mynode(), sp, ep) == -1) {
		return (-1);
	}


	/*
	 * If this node had been joined, withdraw and reset master.
	 *
	 * This could happen if a node was being added to or removed
	 * from a diskset and the node doing the add/delete operation and
	 * all other nodes in the diskset have left the cluster.
	 */
	if (sd->sd_mn_mynode) {
		nd = sd->sd_mn_mynode;
		if (nd->nd_flags & MD_MN_NODE_OWN) {
			if (clnt_withdrawset(mynode(), sp, ep)) {
				rval = -1;
				goto out;
			}
			if (clnt_mnsetmaster(mynode(), sp, "",
			    MD_MN_INVALID_NID, ep)) {
				rval = -1;
				goto out;
			}
		}
	}

	/*
	 * Remove side records for this node (side) from local mddb
	 * (clnt_deldrvs does this) if there are drives in the set.
	 *
	 * Don't need to mark this node as DEL since already marked as
	 * ADD or DEL (or this node would have been chosen as master).
	 * Don't need to mark other node records, drive records or
	 * set records as DEL.  If a panic occurs during clnt_delset,
	 * these records will be deleted the next time this node
	 * becomes a member and goes through the reconfig cycle.
	 */
	/* Get the drive descriptors for this set */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep)) == NULL) {
		if (! mdisok(ep)) {
			/*
			 * Ignore and clear out any failures from
			 * metaget_drivedesc since a panic could have
			 * occurred when a node was partially added to a set.
			 */
			mdclrerror(ep);
		}
	} else {
		if (clnt_deldrvs(mynode(), sp, dd, ep)) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * Now, delete the set - this removes the node, drive
	 * and set records from the local mddb.
	 */
	if (clnt_delset(mynode(), sp, ep)) {
		rval = -1;
		goto out;
	}

out:
	cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/*
	 * Ignore errors from unlock of set since set is no longer
	 * known (if clnt_delset worked).
	 */
	if (clnt_unlock_set(mynode(), cl_sk, &xep) == -1) {
		mdclrerror(&xep);
	}

	cl_set_setkey(NULL);

	metaflushsetname(sp);

	/*
	 * If this node is the lowest numbered nodeid then
	 * call sdssc_create/delete_end depending on whether
	 * this node is marked as ADD or DEL in the node record.
	 */
	if (lowest_alive_nodeid) {
		if (nd->nd_flags & MD_MN_NODE_ADD)
			sdssc_create_end(sp->setname, SDSSC_CLEANUP);
		else if (nd->nd_flags & MD_MN_NODE_DEL)
			sdssc_delete_end(sp->setname, SDSSC_CLEANUP);
	}

	/* Finished with this set -- return */
	return (rval);
}

/*
 * Reconfig step to choose a new master for all MN disksets.
 * Return values:
 *	0 - Everything is great.
 *	1 - This node failed to reconfig.
 *	205 - Cause another reconfig due to a nodelist problem
 *		or RPC failure to another node
 */
int
meta_reconfig_choose_master(
	long		timeout,
	md_error_t	*ep
)
{
	set_t				max_sets, setno;
	int				nodecnt;
	mndiskset_membershiplist_t	*nl;
	md_set_desc			*sd;
	mdsetname_t			*sp;
	int				rval = 0;
	mddb_setflags_config_t		sf;
	int				start_node_delayed = 0;

	if ((max_sets = get_max_sets(ep)) == 0) {
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Unable to get number of sets"));
		return (1);
	}

	/*
	 * Get membershiplist from API routine.  If there's
	 * an error, return a 205 to cause another reconfig.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
		mde_perror(ep, "");
		return (205);
	}

	for (setno = 1; setno < max_sets; setno++) {
		if ((sp = metasetnosetname(setno, ep)) == NULL) {
			if (mdiserror(ep, MDE_NO_SET)) {
				/* No set for this setno - continue */
				mdclrerror(ep);
				continue;
			} else {
				/*
				 * If encountered an RPC error from my node,
				 * then immediately fail.
				 */
				if (mdanyrpcerror(ep)) {
					mde_perror(ep, "");
					return (1);
				}
				/* Can't get set information */
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to get information for "
				    "set number %d"), setno);
				mdclrerror(ep);
				continue;
			}
		}

		/* If setname is there, set desc should exist. */
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			/*
			 * If encountered an RPC error from my node,
			 * then immediately fail.
			 */
			if (mdanyrpcerror(ep)) {
				mde_perror(ep, "");
				return (1);
			}
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Unable to get set %s desc information"),
			    sp->setname);
			mdclrerror(ep);
			continue;
		}

		/* Only reconfig MN disksets */
		if (!MD_MNSET_DESC(sd)) {
			continue;
		}

		meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
		    "Begin choose master for set %s: %s"),
		    sp->setname, meta_print_hrtime(gethrtime() - start_time));

		/* Update nodelist with member information. */
		if (meta_reconfig_update_nodelist(sp, nl, sd, ep)) {
			/*
			 * If encountered an RPC error from my node,
			 * then immediately fail.
			 */
			if (mdanyrpcerror(ep)) {
				mde_perror(ep, "");
				return (1);
			}
			mde_perror(ep, "");
			mdclrerror(ep);
			continue;
		}

		/*
		 * If all nodes in a cluster are starting, then
		 * all nodes will attempt to contact all other nodes
		 * to determine a master node.  This can lead to a
		 * problem where node 1 is trying to contact the rpc.metad
		 * node 2 and node 2 is trying to contact the rpc.metad
		 * on node 1 -- and this causes the rpc call to fail
		 * on both nodes and causes a new reconfig cycle.
		 *
		 * In order to break this problem, a newly starting node
		 * will delay a small amount of time (nodeid mod 4 seconds)
		 * and will then run the code to choose a master for the
		 * first set.  Delay will only be done once regardless of the
		 * number of sets.
		 */
		if (start_node_delayed == 0) {
			(void) memset(&sf, 0, sizeof (sf));
			sf.sf_setno = sp->setno;
			sf.sf_flags = MDDB_NM_GET;
			/* Use magic to help protect ioctl against attack. */
			sf.sf_magic = MDDB_SETFLAGS_MAGIC;
			if ((metaioctl(MD_MN_GET_SETFLAGS, &sf,
			    &sf.sf_mde, NULL) == 0) &&
			    ((sf.sf_setflags & MD_SET_MN_START_RC) ==
			    MD_SET_MN_START_RC)) {
				(void) sleep(sd->sd_mn_mynode->nd_nodeid % 4);
			}
			start_node_delayed = 1;
		}

		/* Choose master for this set */
		rval = meta_reconfig_choose_master_for_set(sp, sd, ep);
		if (rval == -1) {
			mde_perror(ep, "");
			return (1);
		} else if (rval == 205) {
			mde_perror(ep, "");
			return (205);
		}

		/* reinit rpc.mdcommd with new nodelist */
		if (mdmn_reinit_set(sp->setno, timeout)) {
			md_eprintf(dgettext(TEXT_DOMAIN,
			    "Could not re-initialise rpc.mdcommd for "
			    "set %s\n"), sp->setname);
			return (1);
		}

		meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
		    "Choose master for set %s completed: %s"),
		    sp->setname, meta_print_hrtime(gethrtime() - start_time));
	}

	/*
	 * Each node turns on I/Os for all MN disksets.
	 * This is to recover from the situation where the master died
	 * during a previous reconfig cycle when I/Os were suspended
	 * for a MN diskset.
	 * If a failure occurs return a 1 which will force this node to
	 * panic.  Cannot leave node in the situation where I/Os are
	 * not resumed.
	 */
	setno = 0; /* 0 means all MN sets */
	if (metaioctl(MD_MN_RESUME_SET, &setno, ep, NULL)) {
		mde_perror(ep, "");
		return (1);
	}

	/* Free the nodelist */
	if (nodecnt)
		meta_free_nodelist(nl);

	return (0);
}

/*
 * meta_mnsync_user_records will synchronize the diskset user records across
 * all nodes in the diskset.  The diskset user records are stored in
 * each node's local set mddb.
 *
 * This needs to be done even if there is no master change during the
 * reconfig cycle since this routine should clean up any mess left by
 * the untimely termination of a metaset or metadb command (due to a
 * node panic or to user intervention).
 *
 * Caller is the Master node.
 *
 * Returns	 0 - Success
 *		205 - Failure during RPC to another node
 *		-1 - Any other failure and ep is filled in.
 */
int
meta_mnsync_user_records(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	md_mnnode_desc		*master_nodelist, *nd, *nd2, *ndtail;
	md_mnset_record		*mnsr;
	md_mnsr_node_t		*master_mnsr_node = NULL, *mnsr_node = NULL;
	md_mnnode_record	*nr;
	md_drive_record		*dr;
	int			dr_cnt, dd_cnt;
	int			found_my_nr;
	md_drive_desc		*dd, *dd_prev, *master_dd, *other_dd;
	int			all_drives_ok;
	int			rval = 0;
	int			max_genid = 0;
	int			num_alive_nodes, num_alive_nodes_del = 0;
	int			set_locked = 0;
	md_setkey_t		*cl_sk;
	md_error_t		xep = mdnullerror;
	char			*anode[1];
	mddb_setflags_config_t	sf;

	/*
	 * Sync up node records first.
	 * Construct a master nodelist using the nodelist from this
	 * node's rpc.metad node records and then setting the state of each
	 * node following these rules:
	 *	- If a node record is marked OK on its node, mark it OK
	 *		in the master nodelist (and later OK on all nodes)
	 *		If a node record is also marked OWN on its node,
	 *		mark it OWN in the master nodelist.
	 *	- If a node record is not marked OK on its node, then mark
	 *		it as DEL in the master list (later deleting it)
	 *	- If node record doesn't exist on that node, then mark it DEL
	 *		(later deleting it)
	 *	- If set record doesn't exist on that node, mark node as DEL
	 *	- If a node record doesn't exist on all nodes, then mark it DEL
	 *	- If a node is not ALIVE, then
	 *		- If that node marked DEL on any node - mark it DEL
	 *			in master list but leave in nodelist
	 *		- If that node is marked as ADD on any node, mark it
	 *			ADD in the master list but leave in nodelist
	 *		- When that node returns to the living, the DEL
	 *			node record will be removed and the ADD node
	 *			record may be removed if marked ADD on that
	 *			node.
	 * The key rule is to not remove a node from the nodelist until
	 * that node record is removed from its own node.  Do not want to
	 * remove a node's record from all other nodes and then have
	 * that node have its own record marked OK so that a node will pick
	 * a different master than the other nodes.
	 *
	 * Next,
	 * If node is ALIVE and node record is marked DEL in master nodelist,
	 * remove node from set.
	 * If node is ALIVE and node record is marked OK in master nodelist,
	 * mark it OK on all other nodes.
	 * If node is not ALIVE and node record is marked DEL in master
	 * nodelist, mark it DEL on all other nodes.
	 * If node is not ALIVE and node record is marked ADD in master,
	 * nodelist, mark it ADD on all other nodes.
	 */
	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		return (-1);
	}
	master_nodelist = sd->sd_nodelist;

	/*
	 * Walk through nodelist creating a master nodelist.
	 */
	num_alive_nodes = 0;
	nd = master_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		num_alive_nodes++;
		if (clnt_mngetset(nd->nd_nodename, sp->setname,
		    MD_SET_BAD, &mnsr, ep) == -1) {
			if (mdiserror(ep, MDE_NO_SET)) {
				/* set doesn't exist, mark node as DEL */
				nd->nd_flags &= ~MD_MN_NODE_OK;
				nd->nd_flags &= ~MD_MN_NODE_ADD;
				nd->nd_flags |= MD_MN_NODE_DEL;
				nd->nd_flags |= MD_MN_NODE_NOSET;
				nd = nd->nd_next;
				continue;
			} else {
				/* If RPC failure to another node return 205 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}
		}
		/* Find biggest genid in records for this diskset */
		if (mnsr->sr_genid > max_genid)
			max_genid = mnsr->sr_genid;

		dr = mnsr->sr_drivechain;
		while (dr) {
			/* Find biggest genid in records for this diskset */
			if (dr->dr_genid > max_genid) {
				max_genid = dr->dr_genid;
			}
			dr = dr->dr_next;
		}

		found_my_nr = 0;
		nr = mnsr->sr_nodechain;
		/* nr is the list of node recs from nd_nodename node */
		while (nr) {
			/* Find biggest genid in records for this diskset */
			if (nr->nr_genid > max_genid)
				max_genid = nr->nr_genid;
			nd2 = master_nodelist;
			ndtail = NULL;
			/* For each node record, is it in master list? */
			while (nd2) {
				if (nd2->nd_nodeid == nr->nr_nodeid)
					break;
				if (nd2->nd_next == NULL)
					ndtail = nd2;
				nd2 = nd2->nd_next;
			}
			/*
			 * Found node record not in master list -- add it
			 * to list marking it as DEL since node record
			 * should exist on all nodes unless a panic occurred
			 * during addition or deletion of host to diskset.
			 */
			if (nd2 == NULL) {
				nd2 = Zalloc(sizeof (*nd2));
				(void) strcpy(nd2->nd_nodename,
				    nr->nr_nodename);
				nd2->nd_flags = nr->nr_flags;
				nd2->nd_flags |= MD_MN_NODE_DEL;
				nd2->nd_nodeid = nr->nr_nodeid;
				nd2->nd_next = NULL;
				ndtail->nd_next = nd2;
				nd2 = NULL;
				nr = nr->nr_next;
				continue;
			}
			/*
			 * Is this the node record for the node that
			 * we requested the set desc from?
			 * If so, check if node has its own node record
			 * marked OK. If marked OK, check for the OWN bit.
			 */
			if (nr->nr_nodeid == nd->nd_nodeid) {
				found_my_nr = 1;
				if (nr->nr_flags & MD_MN_NODE_OK) {
					/*
					 * If node record is marked OK
					 * on its own node, then mark it OK
					 * in the master list.  Node record
					 * would have to exist on all nodes
					 * in the ADD state before it could
					 * be put into the OK state.
					 */
					nd->nd_flags |= MD_MN_NODE_OK;
					nd->nd_flags &=
					    ~(MD_MN_NODE_ADD | MD_MN_NODE_DEL);
					/*
					 * Mark own in master list as marked
					 * on own node.
					 */
					if (nr->nr_flags & MD_MN_NODE_OWN)
						nd->nd_flags |= MD_MN_NODE_OWN;
					else
						nd->nd_flags &= ~MD_MN_NODE_OWN;
				} else {
					/* Otherwise, mark node as DEL */
					nd->nd_flags &= ~MD_MN_NODE_OK;
					nd->nd_flags &= ~MD_MN_NODE_ADD;
					nd->nd_flags |= MD_MN_NODE_DEL;
				}
			}
			/*
			 * If node is not ALIVE and marked DEL
			 * on any node, make it DEL in master list.
			 * If node is not ALIVE and marked ADD
			 * on any node, make it ADD in master list
			 * unless node record has already been marked DEL.
			 */
			if (!(nr->nr_flags & MD_MN_NODE_ALIVE)) {
				if (nr->nr_flags & MD_MN_NODE_ADD) {
					if (!(nd->nd_flags & MD_MN_NODE_DEL)) {
						/* If not DEL - mark it ADD */
						nd->nd_flags |= MD_MN_NODE_ADD;
						nd->nd_flags &= ~MD_MN_NODE_OK;
					}
				}
				if (nr->nr_flags & MD_MN_NODE_DEL) {
					nd->nd_flags |= MD_MN_NODE_DEL;
					nd->nd_flags &= ~MD_MN_NODE_OK;
					/* Could already be ADD - make it DEL */
					nd->nd_flags &= ~MD_MN_NODE_ADD;
				}
			}
			nr = nr->nr_next;
		}
		/*
		 * If a node record doesn't exist on its own node,
		 * then mark node as DEL.
		 */
		if (found_my_nr == 0) {
			nd->nd_flags &= ~MD_MN_NODE_OK;
			nd->nd_flags |= MD_MN_NODE_DEL;
		}

		/*
		 * If node is OK - put mnsr onto master_mnsr_node list for
		 * later use when syncing up the drive records in the set.
		 */
		if (nd->nd_flags & MD_MN_NODE_OK) {
			mnsr_node = Zalloc(sizeof (*mnsr_node));
			mnsr_node->mmn_mnsr = mnsr;
			(void) strncpy(mnsr_node->mmn_nodename,
			    nd->nd_nodename, MD_MAX_MNNODENAME_PLUS_1);
			mnsr_node->mmn_next = master_mnsr_node;
			master_mnsr_node = mnsr_node;
		} else {
			free_sr((struct md_set_record *)mnsr);
		}

		nd = nd->nd_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Master nodelist created for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	/*
	 * Send master nodelist to the rpc.metad on all nodes (including
	 * myself) and each node will update itself.  This will set the
	 * ADD and DEL flags on each node as setup in the master nodelist.
	 * Don't send nodelist to node where set doesn't exist.
	 */
	nd = master_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE) ||
		    (nd->nd_flags & MD_MN_NODE_NOSET)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_upd_nr_flags(nd->nd_nodename, sp,
		    master_nodelist, MD_NR_SET, MNSET_IN_RECONFIG, ep)) {
			/* If RPC failure to another node return 205 */
			if ((mdanyrpcerror(ep)) &&
			    (sd->sd_mn_mynode->nd_nodeid !=
			    nd->nd_nodeid)) {
				rval = 205;
			} else {
				/* Any other failure */
				rval = -1;
			}
			goto out;
		}
		nd = nd->nd_next;
	}

	/*
	 * Now, delete nodes that need to be deleted.
	 */
	if ((dd = metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep))  == NULL) {
		if (! mdisok(ep)) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * May be doing lots of RPC commands to the nodes, so lock the
	 * ALIVE members of the set since most of the rpc.metad routines
	 * require this for security reasons.
	 */
	nd = master_nodelist;
	while (nd) {
		/* Skip non-alive nodes and node without set */
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE) ||
		    (nd->nd_flags & MD_MN_NODE_NOSET)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
			/* If RPC failure to another node return 205 */
			if ((mdanyrpcerror(ep)) &&
			    (sd->sd_mn_mynode->nd_nodeid !=
			    nd->nd_nodeid)) {
				rval = 205;
			} else {
				/* Any other failure */
				rval = -1;
			}
			goto out;
		}
		set_locked = 1;
		nd = nd->nd_next;
	}

	nd = master_nodelist;
	while (nd) {
		/* Skip non-alive nodes */
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (nd->nd_flags & MD_MN_NODE_DEL) {
			num_alive_nodes_del++;
			/*
			 * Delete this node rec from all ALIVE nodes in diskset.
			 */
			nd2 = master_nodelist;
			while (nd2) {
				/* Skip non-alive nodes and node without set */
				if (!(nd2->nd_flags & MD_MN_NODE_ALIVE) ||
				    (nd2->nd_flags & MD_MN_NODE_NOSET)) {
					nd2 = nd2->nd_next;
					continue;
				}

				/* This is a node being deleted from set */
				if (nd2->nd_nodeid == nd->nd_nodeid) {
					/* Mark set record as DEL */
					if (clnt_upd_sr_flags(nd->nd_nodename,
					    sp, MD_SR_DEL, ep)) {
						/* RPC failure to !my node */
						if ((mdanyrpcerror(ep)) &&
						    (sd->sd_mn_mynode->
						    nd_nodeid
						    != nd->nd_nodeid)) {
							rval = 205;
						} else {
							/* Any other failure */
							rval = -1;
						}
						goto out;
					}
					if (clnt_deldrvs(nd->nd_nodename, sp,
					    dd, ep)) {
						/* RPC failure to !my node */
						if ((mdanyrpcerror(ep)) &&
						    (sd->sd_mn_mynode->
						    nd_nodeid
						    != nd->nd_nodeid)) {
							rval = 205;
						} else {
							/* Any other failure */
							rval = -1;
						}
						goto out;
					}
					if (clnt_delset(nd->nd_nodename, sp,
					    ep) == -1) {
						/* RPC failure to !my node */
						if ((mdanyrpcerror(ep)) &&
						    (sd->sd_mn_mynode->
						    nd_nodeid
						    != nd->nd_nodeid)) {
							rval = 205;
						} else {
							/* Any other failure */
							rval = -1;
						}
						goto out;
					}
				} else {
					/*
					 * Delete host from sets on hosts
					 * not being deleted.
					 */
					anode[0] = Strdup(nd->nd_nodename);
					if (clnt_delhosts(nd2->nd_nodename, sp,
					    1, anode, ep) == -1) {
						Free(anode[0]);
						/* RPC failure to !my node */
						if ((mdanyrpcerror(ep)) &&
						    (sd->sd_mn_mynode->
						    nd_nodeid
						    != nd2->nd_nodeid)) {
							rval = 205;
						} else {
							/* Any other failure */
							rval = -1;
						}
						goto out;
					}

					meta_mc_log(MC_LOG5,
					    dgettext(TEXT_DOMAIN,
					    "Deleted node %s (%d) on node %s "
					    "from set %s: %s"),
					    nd->nd_nodename, nd->nd_nodeid,
					    nd2->nd_nodename,
					    sp->setname,
					    meta_print_hrtime(
					    gethrtime() - start_time));

					Free(anode[0]);
				}
				nd2 = nd2->nd_next;
			}
		}
		nd = nd->nd_next;
	}

	nd = master_nodelist;
	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	while (nd) {
		/* Skip non-alive nodes and node without set */
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE) ||
		    (nd->nd_flags & MD_MN_NODE_NOSET)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_unlock_set(nd->nd_nodename, cl_sk, ep)) {
			/* If RPC failure to another node return 205 */
			if ((mdanyrpcerror(ep)) &&
			    (sd->sd_mn_mynode->nd_nodeid !=
			    nd->nd_nodeid)) {
				rval = 205;
			} else {
				/* Any other failure */
				rval = -1;
			}
			goto out;
		}
		nd = nd->nd_next;
	}
	cl_set_setkey(NULL);
	set_locked = 0;

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Nodelist syncronization complete for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	metaflushsetname(sp);

	/*
	 * If all alive nodes have been deleted from set, just
	 * return since nothing else can be done until non-alive
	 * nodes (if there are any) rejoin the cluster.
	 */
	if (num_alive_nodes == num_alive_nodes_del) {
		rval = 0;
		goto out;
	}

	/*
	 * Sync up drive records.
	 *
	 * If a node panic'd (or metaset command was killed) during the
	 * addition or deletion of a drive to the diskset, the nodes
	 * may have a different view of the drive list.  During cleanup
	 * of the drive list during reconfig, a drive will be deleted
	 * from the list if the master node sees that the drive has been
	 * marked in the ADD state on any node or is marked in the DEL state
	 * on all nodes.
	 * This cleanup must occur even if all nodes in the cluster are
	 * not part of the cluster so that all nodes have the same view
	 * of the drivelist.
	 * Then if the entire cluster goes down and comes back up, the
	 * new master node could be a node that wasn't in the cluster when
	 * the node was deleted.  This could lead to a situation where the
	 * master node thinks that a drive is OK, but this drive isn't
	 * known to the other nodes.
	 * This situation can also occur during the addition of a drive
	 * where a node has the drive marked OK, but the node executing the
	 * metaset command enountered a failure before marking that drive OK
	 * on the rest of the nodes.  If the node with the OK drive then
	 * panics, then rest of the nodes will remove that drive marked ADD
	 * and when the node with the OK drive rejoins the cluster, it will
	 * have a drive marked OK that is unknown by the other nodes.
	 *
	 * There are 2 situations to consider:
	 * A) Master knows about a drive that other nodes don't know about.
	 * B) At least one slave node knows about a drive that the master
	 *    node doesn't know about.
	 *
	 * To handle these situations the following steps are followed:
	 * 1) Count number of drives known by this master node and the
	 *    other slave nodes.
	 *    If all nodes have the same number of drives and the master has
	 *    all drives marked OK, then skip to step4.
	 *
	 * 2) If a node has less drives listed than the master, the master
	 *    must get the drive descriptor list from that node so that
	 *    master can determine which drive it needs to delete from that
	 *    node.  Master must get the drive descriptor list since the
	 *    drive record list does not contain the name of the drive, but
	 *    only a key and the key can only be interprested on that other
	 *    node.
	 *
	 * 3) The master will then create the master drive list by doing:
	 *	- Master starts with drive list known by master.
	 *	- Any drive marked ADD will be removed from the list.
	 *	- Any drive not known by another node (from step2) will be
	 *	removed from the drive list.
	 *	- If a drive is marked DEL on the master, the master must
	 *	verify that the drive record is marked DEL on all nodes.
	 *	If any node has the drive record marked OK, mark it OK
	 *	on the master.  (The reason why is described below).
	 *
	 * 4) The master sends out the master drive list and the slave
	 *    nodes will force their drive lists to match the master
	 *    drive list by deleting drives, if necessary and by changing
	 *    the drive record states from ADD->OK if master has drive
	 *    marked OK and slave has drive marked ADD.
	 *
	 * Interesting scenarios:
	 *
	 * 1) System has 4 nodes with node 1 as the master.  Node 3 starts
	 *    to delete a drive record (drive record on node 1 is marked DEL),
	 *    but is stopped when node 3 panics.  Node 1 also panics.
	 *    During reconfig cycle, node 2 is picked as master and the drive
	 *    record is left alone since all nodes in the cluster have it
	 *    marked OK.  User now sees drive as part of diskset.
	 *    Now, entire cluster is rebooted and node 1 rejoins the cluster.
	 *    Node 1 is picked as the master and node 1 has drive record
	 *    marked DEL.  Node 1 contacts all other nodes in the cluster
	 *    and since at least one node has the drive record marked OK,
	 *    the master marks the drive record OK.
	 *    User continues to see the drive as part of the diskset.
	 */

	/* Reget set descriptor since flushed above */
	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		rval = -1;
		goto out;
	}

	/* Has side effect of setting sd->sd_drvs to same as master_dd */
	if ((master_dd = metaget_drivedesc_sideno(sp,
	    sd->sd_mn_mynode->nd_nodeid,
	    (MD_BASICNAME_OK | PRINT_FAST), ep)) == NULL) {
		/* No drives in list */
		if (!mdisok(ep)) {
			/*
			 * Can't get drive list for this node, so
			 * return -1 causing this node to be removed
			 * cluster config and fixed.
			 */
			rval = -1;
			goto out;
		}
	}

	/* Count the number of drives for all nodes */
	mnsr_node = master_mnsr_node;
	while (mnsr_node) {
		dr_cnt = 0;
		dr = mnsr_node->mmn_mnsr->sr_drivechain;
		while (dr) {
			dr_cnt++;
			dr = dr->dr_next;
		}
		mnsr_node->mmn_numdrives = dr_cnt;
		mnsr_node = mnsr_node->mmn_next;
	}

	/* Count the number of drives for the master; also check flags */
	all_drives_ok = 1;
	dd_cnt = 0;
	dd = master_dd;
	while (dd) {
		dd_cnt++;
		if (!(dd->dd_flags & MD_DR_OK))
			all_drives_ok = 0;
		dd = dd->dd_next;
	}

	/* If all drives are ok, do quick check against number of drives */
	if (all_drives_ok) {
		/* If all nodes have same number of drives, almost done */
		mnsr_node = master_mnsr_node;
		while (mnsr_node) {
			if (mnsr_node->mmn_numdrives != dd_cnt)
				break;
			mnsr_node = mnsr_node->mmn_next;
		}
		/* All nodes have same number of drives, just send flags */
		if (mnsr_node == NULL) {
			goto send_drive_list;
		}
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Begin detailed drive synchronization for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	/* Detailed check required  */
	mnsr_node = master_mnsr_node;
	while (mnsr_node) {
		/* Does slave node have less drives than master? */
		if (mnsr_node->mmn_numdrives < dd_cnt) {
			/* Yes - must determine which drive is missing */
			if (clnt_getdrivedesc(mnsr_node->mmn_nodename, sp,
			    &other_dd, ep)) {
				/* RPC failure to !my node */
				if ((mdanyrpcerror(ep)) &&
				    (strcmp(mynode(), mnsr_node->mmn_nodename)
				    != 0)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Master node %s unable to "
				    "retrieve drive list from node %s"),
				    mynode(), mnsr_node->mmn_nodename);
				goto out;
			}
			mnsr_node->mmn_dd = other_dd;
			dd = master_dd;
			while (dd) {
				if (!(dd->dd_flags & MD_DR_OK)) {
					dd = dd->dd_next;
					continue;
				}
				other_dd = mnsr_node->mmn_dd;
				while (other_dd) {
					/* Convert to devids, when available */
					if (strcmp(other_dd->dd_dnp->cname,
					    dd->dd_dnp->cname) == 0) {
						break;
					}
					other_dd = other_dd->dd_next;
				}
				/*
				 * dd not found on slave so mark it
				 * ADD for later deletion (drives in ADD
				 * state are deleted later in this routine).
				 */
				if (other_dd == NULL) {
					dd->dd_flags = MD_DR_ADD;
				}
				dd = dd->dd_next;
			}

		}
		mnsr_node = mnsr_node->mmn_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Drive check completed for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	dd = master_dd;
	dd_prev = 0;
	while (dd) {
		/* Remove any ADD drives from list */
		if (dd->dd_flags & MD_DR_ADD) {
			if (dd_prev) {
				dd_prev->dd_next = dd->dd_next;
				dd->dd_next = NULL;
				metafreedrivedesc(&dd);
				dd = dd_prev->dd_next;
			} else {
				/*
				 * If removing drive descriptor from head
				 * of linked list, also change sd->sd_drvs.
				 */
				master_dd = sd->sd_drvs = dd->dd_next;
				dd->dd_next = NULL;
				metafreedrivedesc(&dd);
				dd = master_dd;
			}
			/* dd setup in if/else above */
			continue;
		}
		/*
		 * If drive is marked DEL, check all other nodes.
		 * If drive on another node is marked OK, mark drive OK
		 * in master list.  If drive is marked DEL or doesn't exist
		 * on all nodes, remove drive from list.
		 */
		if (dd->dd_flags & MD_DR_DEL) {
			mnsr_node = master_mnsr_node;
			while (mnsr_node) {
				if (mnsr_node->mmn_dd == NULL) {
					if (clnt_getdrivedesc(
					    mnsr_node->mmn_nodename, sp,
					    &other_dd, ep)) {
						/* RPC failure to !my node */
						if ((mdanyrpcerror(ep)) &&
						    (strcmp(mynode(),
						    mnsr_node->mmn_nodename)
						    != 0)) {
							rval = 205;
						} else {
							/* Any other failure */
							rval = -1;
						}
						mde_perror(ep,
						    dgettext(TEXT_DOMAIN,
						    "Master node %s unable "
						    "to retrieve drive list "
						    "from node %s"), mynode(),
						    mnsr_node->mmn_nodename);
						goto out;
					}
					mnsr_node->mmn_dd = other_dd;
				}
				other_dd = mnsr_node->mmn_dd;
				while (other_dd) {
					/* Found drive (OK) from other node */
					if (strcmp(dd->dd_dnp->cname,
					    other_dd->dd_dnp->cname)
					    == 0) {
						/* Drive marked OK */
						if (other_dd->dd_flags &
						    MD_DR_OK) {
							dd->dd_flags = MD_DR_OK;
						}
						break;
					}
					other_dd = other_dd->dd_next;
				}
				if (dd->dd_flags == MD_DR_OK)
					break;

				mnsr_node = mnsr_node->mmn_next;
			}
			/*
			 * If no node had this drive marked OK, delete it.
			 */
			if (dd->dd_flags & MD_DR_DEL) {
				if (dd_prev) {
					dd_prev->dd_next = dd->dd_next;
					dd->dd_next = NULL;
					metafreedrivedesc(&dd);
					dd = dd_prev->dd_next;
				} else {
					/*
					 * If removing drive descriptor from
					 * head of linked list, also change
					 * sd->sd_drvs.
					 */
					master_dd = sd->sd_drvs = dd->dd_next;
					dd->dd_next = NULL;
					metafreedrivedesc(&dd);
					dd = master_dd;
				}
				/* dd setup in if/else above */
				continue;
			}
		}
		dd_prev = dd;
		dd = dd->dd_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Setting drive states completed for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

send_drive_list:
	/*
	 * Set genid on all drives to be the highest value seen.
	 */
	dd = master_dd;
	while (dd) {
		dd->dd_genid = max_genid;
		dd = dd->dd_next;
	}
	/*
	 * Send updated drive list to all alive nodes.
	 * Will also set genid on set and node records to have same
	 * as the drive records.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		/* Skip non-alive nodes */
		if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_upd_dr_reconfig(nd->nd_nodename, sp, master_dd, ep)) {
			/* RPC failure to another node */
			if ((mdanyrpcerror(ep)) &&
			    (sd->sd_mn_mynode->nd_nodeid != nd->nd_nodeid)) {
				rval = 205;
			} else {
				/* Any other failure */
				rval = -1;
			}
			goto out;
		}
		nd = nd->nd_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Sent drive list to all nodes for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	/*
	 * If no drive records left in set and nodes had been joined,
	 * withdraw the nodes.  Always reset the master and mark
	 * all nodes as withdrawn on all nodes.
	 */
	if (master_dd == NULL) {
		/* Reset new master flag since no longer master */
		(void) memset(&sf, 0, sizeof (sf));
		sf.sf_setno = sp->setno;
		sf.sf_setflags = MD_SET_MN_NEWMAS_RC;
		sf.sf_flags = MDDB_NM_RESET;
		/* Use magic to help protect ioctl against attack. */
		sf.sf_magic = MDDB_SETFLAGS_MAGIC;
		/* Ignore failure, failure to reset flag isn't catastrophic */
		(void) metaioctl(MD_MN_SET_SETFLAGS, &sf,
		    &sf.sf_mde, NULL);

		meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
		    "Reset new master flag for " "set %s: %s"),
		    sp->setname, meta_print_hrtime(gethrtime() - start_time));

		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip non-alive nodes  */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_lock_set(nd->nd_nodename, sp, ep)) {
				/* RPC failure to another node */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}
			set_locked = 1;

			/* Withdraw node from set if owner */
			if ((nd->nd_flags & MD_MN_NODE_OWN) &&
			    (clnt_withdrawset(nd->nd_nodename, sp, ep))) {
				/* RPC failure to another node */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}

			/* Mark all nodes as withdrawn on this node */
			if (clnt_upd_nr_flags(nd->nd_nodename, sp,
			    sd->sd_nodelist, MD_NR_WITHDRAW, NULL, ep)) {
				/* RPC failure to another node */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}

			/* Resets master to no-master on this node */
			if (clnt_mnsetmaster(nd->nd_nodename, sp,
			    "", MD_MN_INVALID_NID, ep)) {
				/* RPC failure to another node */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}

			cl_sk = cl_get_setkey(sp->setno, sp->setname);
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, ep)) {
				/* RPC failure to another node */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					rval = 205;
				} else {
					/* Any other failure */
					rval = -1;
				}
				goto out;
			}
			set_locked = 0;
			nd = nd->nd_next;
		}
	}

out:
	/*
	 * If got here and set is still locked, then an error has
	 * occurred and master_nodelist is still valid.
	 * If error is not an RPC error, then unlock.
	 * If error is an RPC error, skip unlocks since this could cause
	 * yet another RPC timeout if a node has failed.
	 * Ignore failures in unlock since unlock is just trying to
	 * clean things up.
	 */
	if ((set_locked) && !(mdanyrpcerror(ep))) {
		nd = master_nodelist;
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		while (nd) {
			/* Skip non-alive nodes */
			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}
			/*
			 * If clnt_unlock fails, just break out since next
			 * reconfig cycle will reset the locks anyway.
			 */
			if (clnt_unlock_set(nd->nd_nodename, cl_sk, &xep)) {
				break;
			}
			nd = nd->nd_next;
		}
		cl_set_setkey(NULL);
	}
	/* Free master_mnsr and drive descs */
	mnsr_node = master_mnsr_node;
	while (mnsr_node) {
		master_mnsr_node = mnsr_node->mmn_next;
		free_sr((md_set_record *)mnsr_node->mmn_mnsr);
		free_rem_dd(mnsr_node->mmn_dd);
		Free(mnsr_node);
		mnsr_node = master_mnsr_node;
	}

	/* Frees sd->sd_drvs (which is also master_dd) */
	metaflushsetname(sp);
	return (rval);
}

/*
 * meta_mnsync_diskset_mddbs
 * Calling node is guaranteed to be an owner node.
 * Calling node is the master node.
 *
 * Master node verifies that ondisk mddb format matches its incore format.
 * If no nodes are joined to set, remove the change log entries.
 * If a node is joined to set, play the change log.
 *
 * Returns	 0 - Success
 *		 1 - Master unable to join to set.
 *		205 - Failure during RPC to another node
 *		-1 - Any other failure and ep is filled in.
 *			-1 return will eventually cause node to panic
 *			in a SunCluster environment.
 */
int
meta_mnsync_diskset_mddbs(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	mddb_config_t		c;
	md_mn_msgclass_t	class;
	mddb_setflags_config_t	sf;
	md_mnnode_desc		*nd, *nd2;
	md_error_t		xep = mdnullerror;
	int			stale_set = 0;

	/* If setname is there, set desc should exist. */
	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Unable to get set %s desc information"), sp->setname);
		return (-1);
	}

	/* Are there drives in the set? */
	if (metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep) == NULL) {
		if (! mdisok(ep)) {
			return (-1);
		}
		/* No drives in set -- nothing to sync up */
		return (0);
	}

	/*
	 * Is master node (which is this node) joined to set?
	 * If master node isn't joined (which means that no nodes
	 * are joined to diskset), remove the change log entries
	 * since no need to replay them - all nodes will have same
	 * view of mddbs since all nodes are reading in the mddbs
	 * from disk.
	 * There is also no need to sync up the master and ondisk mddbs
	 * since master has no incore knowledge.
	 * Need to join master to set in order to flush the change
	 * log entries. Don't need to block I/O during join of master
	 * to set since no other nodes are joined to set and so no I/O
	 * can be occurring.
	 */
	if (!(sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
		/* Join master to set */
		if (clnt_joinset(mynode(), sp,
		    MNSET_IN_RECONFIG, ep)) {
			if (mdismddberror(ep, MDE_DB_STALE)) {
				/*
				 * If STALE, print message and continue on.
				 * Don't do any writes or reads to mddbs
				 * so don't clear change log.
				 */
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Join of master node to STALE set %s"),
				    sp->setname);
				stale_set = 1;
				mdclrerror(ep);
			} else if (mdismddberror(ep, MDE_DB_ACCOK)) {
				/* ACCOK means mediator provided extra vote */
				mdclrerror(ep);
			} else {
				/*
				 * If master is unable to join set, print an
				 * error message.  Don't return failure or node
				 * will panic during cluster reconfig cycle.
				 * Also, withdraw node from set in order to
				 * cleanup from failed join attempt.
				 */
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Join of master node in set %s failed"),
				    sp->setname);
				if (clnt_withdrawset(mynode(), sp, &xep))
					mdclrerror(&xep);
				return (1);
			}
		}
		/*
		 * Master node successfully joined.
		 * Set local copy of flags to OWN and
		 * send owner flag to rpc.metad. If not stale,
		 * flush the change log.
		 */
		sd->sd_mn_mynode->nd_flags |= MD_MN_NODE_OWN;
		if (clnt_upd_nr_flags(mynode(), sp, sd->sd_nodelist, MD_NR_SET,
		    MNSET_IN_RECONFIG, ep)) {
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Flag update of master node join in set %s failed"),
			    sp->setname);
			return (-1);
		}

		if (!stale_set) {
			if (mdmn_reset_changelog(sp, ep,
			    MDMN_CLF_RESETLOG) != 0) {
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to reset changelog."));
				return (-1);
			}
			meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
			    "Removed changelog entries for set %s: %s"),
			    sp->setname,
			    meta_print_hrtime(gethrtime() - start_time));
		}
		/* Reset new master flag before return */
		(void) memset(&sf, 0, sizeof (sf));
		sf.sf_setno = sp->setno;
		sf.sf_setflags = MD_SET_MN_NEWMAS_RC;
		sf.sf_flags = MDDB_NM_RESET;
		/* Use magic to help protect ioctl against attack. */
		sf.sf_magic = MDDB_SETFLAGS_MAGIC;
		/* Ignore failure, failure to reset flag isn't catastrophic */
		(void) metaioctl(MD_MN_SET_SETFLAGS, &sf,
		    &sf.sf_mde, NULL);

		meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
		    "Reset new master flag for set %s: %s"),
		    sp->setname, meta_print_hrtime(gethrtime() - start_time));

		return (0);
	}

	/*
	 * Is master already joined to STALE set (< 50% mddbs avail)?
	 * If so, can make no config changes to mddbs so don't check or play
	 * changelog and don't sync master node to ondisk mddbs.
	 * To get out of the stale state all nodes must be withdrawn
	 * from set.  Then as nodes are re-joined, all nodes will
	 * have same view of mddbs since all nodes are reading the
	 * mddbs from disk.
	 */
	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;
	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c.c_mde);
		return (-1);
	}
	if (c.c_flags & MDDB_C_STALE) {
		return (0);
	}

	/*
	 * If this node is NOT a newly chosen master, then there's
	 * nothing else to do since the change log should be empty and
	 * the ondisk and incore mddbs are already consistent.
	 *
	 * A newly chosen master is a node that was not the master
	 * at the beginning of the reconfig cycle.  If a node is a new
	 * master, then the new master state is reset after the ondisk
	 * and incore mddbs are consistent and the change log has
	 * been replayed.
	 */
	(void) memset(&sf, 0, sizeof (sf));
	sf.sf_setno = sp->setno;
	sf.sf_flags = MDDB_NM_GET;
	/* Use magic to help protect ioctl against attack. */
	sf.sf_magic = MDDB_SETFLAGS_MAGIC;
	if ((metaioctl(MD_MN_GET_SETFLAGS, &sf, &sf.sf_mde, NULL) == 0) &&
	    ((sf.sf_setflags & MD_SET_MN_NEWMAS_RC) == 0)) {
		return (0);
	}

	/*
	 * Now, sync up incore master view to ondisk mddbs.
	 * This is needed in the case where a master node
	 * had made a change to the mddb, but this change
	 * may not have been relayed to the slaves yet.
	 * So, the new master needs to verify that the ondisk
	 * mddbs match what the new master has incore -
	 * if different, new master rewrites all of the mddbs.
	 * Then the new master will replay the changelog and the
	 * new master will then execute what the old master had
	 * done.
	 *
	 * Block all I/Os to disks in this diskset on all nodes in
	 * the diskset.  This will allow the rewriting of the mddbs
	 * (if needed), to proceed in a timely manner.
	 *
	 * If block of I/Os fail, return a -1.
	 */

	nd = sd->sd_nodelist;
	while (nd) {
		/* Skip non-alive and non-owner nodes  */
		if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) ||
		    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_mn_susp_res_io(nd->nd_nodename, sp->setno,
		    MN_SUSP_IO, ep)) {
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Unable to suspend I/O on node %s in set %s"),
			    nd->nd_nodename, sp->setname);

			/*
			 * Resume all other nodes that had been suspended.
			 * (Reconfig return step also resumes I/Os
			 * for all sets.)
			 */
			nd2 = sd->sd_nodelist;
			while (nd2) {
				/* Stop when reaching failed node */
				if (nd2->nd_nodeid == nd->nd_nodeid)
					break;
				/* Skip non-alive and non-owner nodes  */
				if ((!(nd2->nd_flags & MD_MN_NODE_ALIVE)) ||
				    (!(nd2->nd_flags & MD_MN_NODE_OWN))) {
					nd2 = nd2->nd_next;
					continue;
				}
				(void) (clnt_mn_susp_res_io(nd2->nd_nodename,
				    sp->setno, MN_RES_IO, &xep));
				nd2 = nd2->nd_next;
			}

			/*
			 * If an RPC failure on another node, return a 205.
			 * Otherwise, exit with failure.
			 */
			if ((mdanyrpcerror(ep)) &&
			    (sd->sd_mn_mynode->nd_nodeid !=
			    nd->nd_nodeid)) {
				return (205);
			} else {
				return (-1);
			}

		}
		nd = nd->nd_next;
	}

	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;
	/* Master can't sync up to ondisk mddbs?  Kick it out of cluster */
	if (metaioctl(MD_MN_CHK_WRT_MDDB, &c, &c.c_mde, NULL) != 0)
		return (-1);

	/*
	 * Resume I/Os that were suspended above.
	 */
	nd = sd->sd_nodelist;
	while (nd) {
		/* Skip non-alive and non-owner nodes  */
		if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) ||
		    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
			nd = nd->nd_next;
			continue;
		}
		if (clnt_mn_susp_res_io(nd->nd_nodename, sp->setno,
		    MN_RES_IO, ep)) {
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Unable to resume I/O on node %s in set %s"),
			    nd->nd_nodename, sp->setname);

			/*
			 * If an RPC failure then don't do any
			 * more RPC calls, since one timeout is enough
			 * to endure.  If RPC failure to another node, return
			 * 205.  If RPC failure to my node, return -1.
			 * If not an RPC failure, continue resuming the
			 * rest of the nodes and then return -1.
			 */
			if (mdanyrpcerror(ep)) {
				if (sd->sd_mn_mynode->nd_nodeid ==
				    nd->nd_nodeid) {
					return (-1);
				} else {
					return (205);
				}
			}

			/*
			 * If not an RPC error, continue resuming rest of
			 * nodes, ignoring any failures except for an
			 * RPC failure which constitutes an immediate exit.
			 * Start in middle of list with failing node.
			 */
			nd2 = nd->nd_next;
			while (nd2) {
				/* Skip non-alive and non-owner nodes  */
				if ((!(nd2->nd_flags & MD_MN_NODE_ALIVE)) ||
				    (!(nd2->nd_flags & MD_MN_NODE_OWN))) {
					nd2 = nd2->nd_next;
					continue;
				}
				(void) (clnt_mn_susp_res_io(nd2->nd_nodename,
				    sp->setno, MN_RES_IO, &xep));
				if (mdanyrpcerror(&xep)) {
					return (-1);
				}
				nd2 = nd2->nd_next;
			}
		}
		nd = nd->nd_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN, "Master node has completed "
	    "checking/writing the mddb for set %s: %s"), sp->setname,
	    meta_print_hrtime(gethrtime() - start_time));

	/*
	 * Send (aka replay) all messages we find in the changelog.
	 * Flag the messages with
	 *   MD_MSGF_REPLAY_MSG, so no new message ID is generated for them
	 *   MD_MSGF_OVERRIDE_SUSPEND so they can pass the suspended commd.
	 */
	for (class = MD_MN_NCLASSES - 1; class > 0; class--) {
		mdmn_changelog_record_t	*lr;
		md_error_t	xep = mdnullerror;
		md_mn_result_t	*resultp = NULL;
		int		ret;

		lr = mdmn_get_changelogrec(sp->setno, class);
		if ((lr->lr_flags & MD_MN_LR_INUSE) == 0) {
			/* no entry for this class */
			continue;
		}

		meta_mc_log(MC_LOG1, dgettext(TEXT_DOMAIN,
		    "replaying message ID=(%d, 0x%llx-%d)\n"),
		    MSGID_ELEMS(lr->lr_msg.msg_msgid));

		ret = mdmn_send_message_with_msgid(
		    lr->lr_msg.msg_setno,
		    lr->lr_msg.msg_type,
		    lr->lr_msg.msg_flags | MD_MSGF_REPLAY_MSG |
		    MD_MSGF_OVERRIDE_SUSPEND,
		    lr->lr_msg.msg_recipient,
		    lr->lr_msg.msg_event_data,
		    lr->lr_msg.msg_event_size,
		    &resultp,
		    &lr->lr_msg.msg_msgid,
		    &xep);

		meta_mc_log(MC_LOG1, dgettext(TEXT_DOMAIN,
		    "mdmn_send_message returned %d\n"), ret);

		if (resultp)
			free_result(resultp);
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Playing changelog completed for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	/*
	 * Now that new master has ondisk and incore mddbs in sync, reset
	 * this node's new master kernel flag (for this set).  If this node
	 * re-enters another reconfig cycle before the completion of this
	 * reconfig cycle, this master node won't need to check if the ondisk
	 * and incore mddbs are in sync since this node won't be considered
	 * a new master (since this flag is being reset here in the middle of
	 * step2).  This will save time during any subsequent reconfig
	 * cycles as long as this node continues to be master.
	 */
	(void) memset(&sf, 0, sizeof (sf));
	sf.sf_setno = sp->setno;
	sf.sf_setflags = MD_SET_MN_NEWMAS_RC;
	sf.sf_flags = MDDB_NM_RESET;
	/* Use magic to help protect ioctl against attack. */
	sf.sf_magic = MDDB_SETFLAGS_MAGIC;
	/* Ignore failure, since failure to reset flag isn't catastrophic */
	(void) metaioctl(MD_MN_SET_SETFLAGS, &sf, &sf.sf_mde, NULL);

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Reset new master flag for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	return (0);
}

/*
 * meta_mnjoin_all will join all starting nodes in the diskset.
 * A starting node is considered to be any node that is not
 * an owner of the set but is a member of the cluster.
 * Master node is already joined to set (done in meta_mnsync_diskset_mddbs).
 *
 * Caller is the Master node.
 *
 * Returns	 0 - Success
 *		205 - Failure during RPC to another node
 *		-1 - Any other failure and ep is filled in.
 */
int
meta_mnjoin_all(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	md_mnnode_desc		*nd, *nd2;
	int			rval = 0;
	int			stale_flag = 0;
	mddb_config_t		c;
	int			susp_res_flag = 0;
	md_error_t		xep = mdnullerror;

	/* If setname is there, set desc should exist. */
	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Unable to get set %s desc information"), sp->setname);
		return (-1);
	}

	/* Are there drives in the set? */
	if (metaget_drivedesc(sp, (MD_BASICNAME_OK | PRINT_FAST),
	    ep) == NULL) {
		if (! mdisok(ep)) {
			return (-1);
		}
		/* No drives in set -- nothing to join */
		return (0);
	}

	/*
	 * Is set currently stale?
	 */
	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;
	/* Ignore failure since master node may not be joined yet */
	(void) metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL);
	if (c.c_flags & MDDB_C_STALE) {
		stale_flag = MNSET_IS_STALE;
	}

	/*
	 * If any nodes are going to be joined to diskset, then
	 * suspend I/O to all disks in diskset so that nodes can join
	 * (read in mddbs) in a reasonable amount of time even under
	 * high I/O load.  Don't need to do this if set is STALE since
	 * no I/O can be occurring to a STALE set.
	 */
	if (stale_flag != MNSET_IS_STALE) {
		nd = sd->sd_nodelist;
		while (nd) {
			/* Found a node that will be joined to diskset */
			if ((nd->nd_flags & MD_MN_NODE_ALIVE) &&
			    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
				/* Set flag that diskset should be suspended */
				susp_res_flag = 1;
				break;
			}
			nd = nd->nd_next;
		}
	}

	if (susp_res_flag) {
		/*
		 * Block all I/Os to disks in this diskset on all joined
		 * nodes in the diskset.
		 * If block of I/Os fails due to an RPC failure on another
		 * node, return 205; otherwise, return -1.
		 */
		nd = sd->sd_nodelist;
		while (nd) {
			/* Skip non-alive and non-owner nodes  */
			if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) ||
			    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mn_susp_res_io(nd->nd_nodename, sp->setno,
			    MN_SUSP_IO, ep)) {
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to suspend I/O on node %s"
				    " in set %s"), nd->nd_nodename,
				    sp->setname);
				/*
				 * Resume other nodes that had been suspended.
				 * (Reconfig return step also resumes I/Os
				 * for all sets.)
				 */
				nd2 = sd->sd_nodelist;
				while (nd2) {
					/* Stop when reaching failed node */
					if (nd2->nd_nodeid == nd->nd_nodeid)
						break;
					/* Skip non-alive/non-owner nodes  */
					if ((!(nd2->nd_flags &
					    MD_MN_NODE_ALIVE)) ||
					    (!(nd2->nd_flags &
					    MD_MN_NODE_OWN))) {
						nd2 = nd2->nd_next;
						continue;
					}
					(void) (clnt_mn_susp_res_io(
					    nd2->nd_nodename, sp->setno,
					    MN_RES_IO, &xep));
					nd2 = nd2->nd_next;
				}

				/*
				 * If the suspend failed due to an
				 * RPC failure on another node, return
				 * a 205.
				 * Otherwise, exit with failure.
				 * The return reconfig step will resume
				 * I/Os for all disksets.
				 */
				if ((mdanyrpcerror(ep)) &&
				    (sd->sd_mn_mynode->nd_nodeid !=
				    nd->nd_nodeid)) {
					return (205);
				} else {
					return (-1);
				}
			}
			nd = nd->nd_next;
		}
	}

	nd = sd->sd_nodelist;
	while (nd) {
		/*
		 * If a node is in the membership list but isn't joined
		 * to the set, try to join the node.
		 */
		if ((nd->nd_flags & MD_MN_NODE_ALIVE) &&
		    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
			if (clnt_joinset(nd->nd_nodename, sp,
			    (MNSET_IN_RECONFIG | stale_flag), ep)) {
				/*
				 * If RPC failure to another node
				 * then exit without attempting anything else.
				 * (Reconfig return step will resume I/Os
				 * for all sets.)
				 */
				if (mdanyrpcerror(ep)) {
					mde_perror(ep, "");
					return (205);
				}
				/*
				 * STALE and ACCOK failures aren't true
				 * failures.  STALE means that <50% mddbs
				 * are available. ACCOK means that the
				 * mediator provided the extra vote.
				 * If a true failure, then print messasge
				 * and withdraw node from set in order to
				 * cleanup from failed join attempt.
				 */
				if ((!mdismddberror(ep, MDE_DB_STALE)) &&
				    (!mdismddberror(ep, MDE_DB_ACCOK))) {
					mde_perror(ep,
					    "WARNING: Unable to join node %s "
					    "to set %s", nd->nd_nodename,
					    sp->setname);
					mdclrerror(ep);
					if (clnt_withdrawset(nd->nd_nodename,
					    sp, &xep))
						mdclrerror(&xep);
					nd = nd->nd_next;
					continue;
				}
			}
			/* Set owner flag even if STALE or ACCOK */
			nd->nd_flags |= MD_MN_NODE_OWN;
		}
		nd = nd->nd_next;
	}
	/*
	 * Resume I/Os if suspended above.
	 */
	if (susp_res_flag) {
		nd = sd->sd_nodelist;
		while (nd) {
			/*
			 * Skip non-alive and non-owner nodes
			 * (this list doesn't include any of
			 * the nodes that were joined).
			 */
			if ((!(nd->nd_flags & MD_MN_NODE_ALIVE)) ||
			    (!(nd->nd_flags & MD_MN_NODE_OWN))) {
				nd = nd->nd_next;
				continue;
			}
			if (clnt_mn_susp_res_io(nd->nd_nodename, sp->setno,
			    MN_RES_IO, ep)) {
				mde_perror(ep, dgettext(TEXT_DOMAIN,
				    "Unable to resume I/O on node %s"
				    " in set %s"), nd->nd_nodename,
				    sp->setname);

				/*
				 * If an RPC failure then don't do any
				 * more RPC calls, since one timeout is enough
				 * to endure.  If RPC failure to another node,
				 * return 205.  If RPC failure to my node,
				 * return -1.
				 * (Reconfig return step will resume I/Os
				 * for all sets.)
				 * If not an RPC failure, continue resuming the
				 * rest of the nodes and then return -1.
				 */
				if (mdanyrpcerror(ep)) {
					if (sd->sd_mn_mynode->nd_nodeid ==
					    nd->nd_nodeid) {
						return (-1);
					} else {
						return (205);
					}
				}

				/*
				 * If not an RPC error, continue resuming rest
				 * of nodes, ignoring any failures except for
				 * an RPC failure which constitutes an
				 * immediate exit.
				 * Start in middle of list with failing node.
				 */
				nd2 = nd->nd_next;
				while (nd2) {
					/* Skip non-owner nodes  */
					if ((!(nd2->nd_flags &
					    MD_MN_NODE_ALIVE)) ||
					    (!(nd2->nd_flags &
					    MD_MN_NODE_OWN))) {
						nd2 = nd2->nd_next;
						continue;
					}
					(void) (clnt_mn_susp_res_io(
					    nd2->nd_nodename, sp->setno,
					    MN_RES_IO, &xep));
					if (mdanyrpcerror(&xep)) {
						return (-1);
					}
					nd2 = nd2->nd_next;
				}
			}
			nd = nd->nd_next;
		}
	}

	nd = sd->sd_nodelist;
	while (nd) {
		if (!(nd->nd_flags & MD_MN_NODE_OWN)) {
			nd = nd->nd_next;
			continue;
		}
		/*
		 * If 1 node fails - go ahead and update the rest except
		 * in the case of an RPC failure, fail immediately.
		 */
		if (clnt_upd_nr_flags(nd->nd_nodename, sp,
		    sd->sd_nodelist, MD_NR_SET, MNSET_IN_RECONFIG, ep)) {
			/* RPC failure to another node */
			if (mdanyrpcerror(ep)) {
				return (205);
			}
			nd = nd->nd_next;
			rval = -1;
			continue;
		}
		nd = nd->nd_next;
	}

	meta_mc_log(MC_LOG5, dgettext(TEXT_DOMAIN,
	    "Join of all nodes completed for set %s: %s"),
	    sp->setname, meta_print_hrtime(gethrtime() - start_time));

	return (rval);
}
