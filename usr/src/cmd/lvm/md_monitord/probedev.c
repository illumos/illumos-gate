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

#include "md_monitord.h"

#define	MD_PROBE_OPEN_T "probe open test"

/*
 * Failure return's a 1
 */
int
hotspare_ok(char *bname)
{
	int fd;
	char buf[512];

	if ((fd = open(bname, O_RDONLY)) < 0)
		return (0);
	if (read(fd, buf, sizeof (buf)) < 0) {
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (1);
}

void
delete_hotspares_impl(mdhspname_t *hspnp, md_hsp_t *hspp, boolean_e verbose)
{
	md_hs_t *hsp;
	uint_t		hsi;
	char    *cname, *bname, *hs_state;
	md_error_t e = mdnullerror;
	int deleted_hs = 0;

	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		mdnamelist_t *nlp;

		hsp = &hspp->hotspares.hotspares_val[hsi];
		if (verbose == True)
			monitord_print(6, "hsi %d\n", hsi);
		cname = hsp->hsnamep->cname;
		bname = hsp->hsnamep->bname;
		nlp = NULL;
		metanamelist_append(&nlp, hsp->hsnamep);
		hs_state = hs_state_to_name(hsp, NULL);
		/* print hotspare */
		if (verbose == True)
			monitord_print(6, "\t%-19s\t%-19s\t%-12s\n",
			    cname, bname, hs_state);
		if (hsp->state == HSS_AVAILABLE) {
			if (hotspare_ok(bname))
				continue;

			monitord_print(6, gettext(
			    "NOTICE: Hotspare %s in %s has failed.\n"
			    "\tDeleting %s since it is not in use\n\n"),
			    bname, hspnp->hspname, bname);

			if (meta_hs_delete(sp, hspnp, nlp, 0, &e) != NULL) {
				mde_perror(&e, "");
			} else {
				deleted_hs++;
			}
		} else {
			if (verbose == True)
				monitord_print(6, gettext(
				    "%s in use - skipping\n"), cname);
		}
	}
}



/*
 * Generic routine to issue probe ioctls
 */

int
md_probe_ioctl(mdnamelist_t *nlp, int ndevs, char *drvname, boolean_e verbose)
{
	mdnamelist_t	*p;
	mdname_t	*np;
	md_probedev_t	probe_ioc, *iocp;
	int		i, retval = 0;
	/*
	 * Allocate space for all the metadevices and fill in
	 * the minor numbers.
	 */

	memset(&probe_ioc, 0, sizeof (probe_ioc));
	iocp = &probe_ioc;

	if ((iocp->mnum_list = (uintptr_t)calloc(ndevs, sizeof (minor_t)))
	    == 0) {
		monitord_print(0, "md_probe_ioctl: calloc");
		return (-1);
	}

	(void) strcpy(iocp->test_name, MD_PROBE_OPEN_T);
	MD_SETDRIVERNAME(&probe_ioc, drvname, sp->setno);

	if (verbose == True) {
		monitord_print(6, "\n\nmd_probe_ioctl: %s: %s\n",
		    (strcmp(sp->setname, MD_LOCAL_NAME) == 0) ?
		    gettext("local_set") :
		    sp->setname, iocp->md_driver.md_drivername);
	}

	iocp->nmdevs = ndevs;
	if (verbose == True)
		monitord_print(6, "...ndevs 0x%x\n", ndevs);

	for (p = nlp, i = 0; p; p = p->next, i++) {
		np = p->namep;
		((minor_t *)(uintptr_t)iocp->mnum_list)[i] =
		    meta_getminor(np->dev);
		if (verbose == True)
			monitord_print(6, "...%s 0x%lx\n", np->cname,
			    ((minor_t *)(uintptr_t)iocp->mnum_list)[i]);
	}


	if (issue_ioctl == True) {
		if (metaioctl(MD_IOCPROBE_DEV, iocp, &(iocp->mde), NULL) != 0)
			retval = -1;
	}
	return (retval);
}
/*
 *
 *  - remove p from nlp list
 *  - put it on the toplp list.
 *  - update the p to the next element
 */

void
add_to_list(mdnamelist_t **curpp, mdnamelist_t **prevpp,
		mdnamelist_t **newlpp)
{
	mdnamelist_t	*p, *prevp, *nlp;

	p = *curpp;
	prevp = *prevpp;
	nlp = *newlpp;

	if (prevp == p) {
		/* if first element reset prevp */
			prevp = p->next;
			p->next = nlp;
			nlp = p;
			p = prevp;
	} else {
		prevp->next = p->next;
		p->next = nlp;
		nlp = p;
		p = prevp->next;
	}
	*curpp = p;
	*prevpp = prevp;
	*newlpp = nlp;
}
/*
 * Scans the given list of metadeivces and returns a list of top level
 * metadevices.
 * Note: The orignal list is not valid at the end and is set to NULL.
 */

int
get_toplevel_mds(mdnamelist_t **lpp, mdnamelist_t **top_pp, boolean_e verbose)
{
	mdnamelist_t	*p, *prevp, *toplp;
	int		ntopmd, i;
	md_common_t	*mdp;
	md_error_t	e = mdnullerror;

	i = ntopmd = 0;
	prevp = p = *lpp;
	toplp = NULL;

	while (p) {
		if ((mdp = meta_get_unit(sp, p->namep, &e)) == NULL) {
			if (verbose == True)
				monitord_print(6, gettext(
				    "......error on (%d)%s\n"), i,
				    p->namep->devicesname);
				prevp = p;
				p = p->next;
				continue;
		}

		if (mdp->parent == MD_NO_PARENT) {
			/* increment the top level md count. */
			ntopmd++;
			add_to_list(&p, &prevp, &toplp);
		} else {
			prevp = p;
			p = p->next;
		}
		i++;
	}

	*lpp = NULL;
	*top_pp = toplp;

	return (ntopmd);
}

int
get_namelist(mdnamelist_t **transdevlist, mdnamelist_t **devlist,
					char *dev_type)
{
	mdnamelist_t *np, *prevp;
	md_error_t	e = mdnullerror;
	char		*type_name;
	int		i = 0;

	prevp = np = *transdevlist;
	while (np) {
		if ((type_name = metagetmiscname(np->namep, &e)) == NULL) {
			*devlist = NULL;
			return (-1);
		}
		if (strcmp(type_name, dev_type) == 0) {
			/* move it to the devlist */
			add_to_list(&np, &prevp, devlist);
			i++;
		} else {
			prevp = np;
			np = np->next;
		}
	}
	return (i);
}


mdnamelist_t *
create_nlp()
{
	mdnamelist_t *np;

	if (np = (mdnamelist_t *)malloc(sizeof (mdnamelist_t))) {
		np->next = NULL;
		return (np);
	} else {
		/* error condition below */
		monitord_print(0, gettext(
		    "create_nlp: malloc failed\n"));
		monitord_exit(errno);
	}
	return (0);
}

/*
 * Create a list of metadevices associated with trans. top_pp points to
 * this list. The number of components in the list are also returned.
 */
int
create_trans_compslist(mdnamelist_t **lpp, mdnamelist_t **top_pp,
							boolean_e verbose)
{
	mdnamelist_t	*p, *tailp, *toplp, *newlp;
	int		ntoptrans;
	md_error_t	e = mdnullerror;
	md_trans_t	*tp;

	ntoptrans = 0;
	p = *lpp;
	tailp = toplp = NULL;
	/*
	 * Scan the current list of trans devices. From that
	 * extract all the lower level metadevices and put them on
	 * toplp list.
	 */

	while (p) {
		if (tp = meta_get_trans(sp, p->namep, &e)) {
			/*
			 * Check the master and log devices to see if they
			 * are metadevices
			 */
			if (metaismeta(tp->masternamep)) {
				if (verbose == True)
					monitord_print(6, gettext(
					    "master metadevice\n"));
				/* get a mdnamelist_t. */
				newlp = create_nlp();
				newlp->namep = tp->masternamep;
				if (toplp == NULL) {
					toplp = tailp = newlp;
				} else {
					tailp->next = newlp;
					tailp = newlp;
				}
				ntoptrans++;
			}

			if (tp->lognamep && metaismeta(tp->lognamep)) {
				if (verbose == True)
					monitord_print(6, gettext(
					    "log metadevice\n"));
				newlp = create_nlp();
				newlp->namep = tp->lognamep;
				if (toplp == NULL) {
					toplp = tailp = newlp;
				} else {
					tailp->next = newlp;
					tailp = newlp;
				}
				ntoptrans++;
			}
			p = p->next;
		}
	}
	*top_pp = toplp;
	return (ntoptrans);
}

void
probe_mirror_devs(boolean_e verbose)
{
	mdnamelist_t	*nlp, *toplp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;

	if (meta_get_mirror_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * We have some mirrors to probe
		 * get a list of top-level mirrors
		 */

		cnt = get_toplevel_mds(&nlp, &toplp, verbose);
		if (cnt && (md_probe_ioctl(toplp, cnt,
		    MD_MIRROR, verbose) < 0))
			monitord_print(0, gettext(
			    "probe_mirror_devs: "
			    "mirror components %d ioctl error\n"),
			    cnt);

	}

	metafreenamelist(nlp);
	metafreenamelist(toplp);
}

void
probe_raid_devs(boolean_e verbose)
{
	mdnamelist_t	*nlp, *toplp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;

	if (meta_get_raid_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * We have some mirrors to probe
		 * get a list of top-level mirrors
		 */

		cnt = get_toplevel_mds(&nlp, &toplp, verbose);

		if (cnt && (md_probe_ioctl(toplp, cnt,
		    MD_RAID, verbose) < 0))
			monitord_print(0, gettext(
			    "probe_raid_devs: "
			    "RAID-5 components %d ioctl error\n"),
			    cnt);

	}

	metafreenamelist(nlp);
	metafreenamelist(toplp);
}

/*
 * Trans probes are different. -- so whats new.
 * we separate out the master and log device and then issue the
 * probe calls.
 * Since the underlying device could be disk, stripe, RAID or miror,
 * we have to sort them out and then call the ioctl for each.
 */

void
probe_trans_devs(boolean_e verbose)
{
	mdnamelist_t	*nlp, *toplp;
	mdnamelist_t	*trans_raidlp, *trans_mmlp, *trans_stripelp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;
	trans_raidlp = trans_mmlp = trans_stripelp = NULL;

	if (meta_get_trans_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * get a list of master and log metadevices.
		 */

		cnt = create_trans_compslist(&nlp, &toplp, verbose);
		if (verbose == True) {
			int i;

			for (i = 0, nlp = toplp; i < cnt; i++) {
				monitord_print(6, gettext(
				    "tran: underlying drv %s\n"),
				    (nlp->namep)->cname);
				nlp = nlp->next;
			}
		}

		/* underlying RAID-5 components */

		cnt = get_namelist(&toplp, &trans_raidlp, MD_RAID);
		if ((cnt > 0) && (md_probe_ioctl(trans_raidlp, cnt,
		    MD_RAID, verbose) < 0))
			monitord_print(0, gettext(
			    "probe_trans_devs: "
			    "RAID-5 components %d ioctl error\n"),
			    cnt);
		metafreenamelist(trans_raidlp);

		/* underlying mirror components */

		cnt = get_namelist(&toplp, &trans_mmlp, MD_MIRROR);

		if ((cnt > 0) && (md_probe_ioctl(trans_mmlp, cnt,
		    MD_MIRROR, verbose) < 0))
			monitord_print(0, gettext(
			    "probe_trans_devs: "
			    "mirror components %d ioctl error\n"),
			    cnt);
		metafreenamelist(trans_mmlp);

		/* underlying stripe components */

		cnt = get_namelist(&toplp, &trans_stripelp, MD_STRIPE);
		if ((cnt > 0) && (md_probe_ioctl(trans_stripelp, cnt,
		    MD_STRIPE, verbose) < 0))
			monitord_print(0, gettext(
			    "probe_trans_devs: "
			    "stripe components %d ioctl error\n"),
			    cnt);

		metafreenamelist(trans_stripelp);
		metafreenamelist(nlp);
	}

}

/*
 * probe hot spares. This is differs from other approaches since
 * there are no read/write routines through md. We check at the physical
 * component level and then delete it if its bad.
 */

void
probe_hotspare_devs(boolean_e verbose)
{
	mdhspnamelist_t *hspnlp = NULL;
	int		cnt;
	mdhspnamelist_t	*p;
	md_hsp_t	*hspp;
	md_error_t	e = mdnullerror;

	if ((cnt = meta_get_hsp_names(sp, &hspnlp, 0, &e)) < 0) {
		mderror(&e, MDE_UNIT_NOT_FOUND, NULL);
		return;
	} else if (cnt == 0) {
		mderror(&e, MDE_NO_HSPS, NULL);
		return;
	}
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;

		if (verbose == True)
			monitord_print(6, "%s %s\n", gettext("name"),
			    hspnp->hspname);

		if ((hspp = meta_get_hsp(sp, hspnp, &e)) == NULL)
			continue;

		if (hspp->hotspares.hotspares_len != 0) {
			if (verbose == True)
				monitord_print(6, " %u hotspares\n",
				    hspp->hotspares.hotspares_len);
			delete_hotspares_impl(hspnp, hspp, verbose);
		}
	}
	metafreehspnamelist(hspnlp);
}
