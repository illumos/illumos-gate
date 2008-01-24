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
 * Data-Link Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/modhash.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/ctype.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

static kmem_cache_t	*i_dls_vlan_cachep;
static mod_hash_t	*i_dls_vlan_hash;
static mod_hash_t	*i_dls_vlan_dev_hash;
static krwlock_t	i_dls_vlan_lock;
static uint_t		i_dls_vlan_count;

#define	VLAN_HASHSZ	67	/* prime */

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_dls_vlan_constructor(void *buf, void *arg, int kmflag)
{
	dls_vlan_t	*dvp = buf;

	bzero(buf, sizeof (dls_vlan_t));
	mutex_init(&dvp->dv_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_dls_vlan_destructor(void *buf, void *arg)
{
	dls_vlan_t	*dvp = buf;

	ASSERT(dvp->dv_ref == 0);
	ASSERT(dvp->dv_zone_ref == 0);
	mutex_destroy(&dvp->dv_lock);
}

/*
 * Module initialization functions.
 */
void
dls_vlan_init(void)
{
	/*
	 * Create a kmem_cache of dls_vlan_t structures.
	 */
	i_dls_vlan_cachep = kmem_cache_create("dls_vlan_cache",
	    sizeof (dls_vlan_t), 0, i_dls_vlan_constructor,
	    i_dls_vlan_destructor, NULL, NULL, NULL, 0);
	ASSERT(i_dls_vlan_cachep != NULL);

	/*
	 * Create a hash table, keyed by dv_spa, of dls_vlan_t.
	 */
	i_dls_vlan_hash = mod_hash_create_extended("dls_vlan_hash",
	    VLAN_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	/*
	 * Create a hash table, keyed by dv_dev, of dls_vlan_t.
	 */
	i_dls_vlan_dev_hash = mod_hash_create_ptrhash("dls_vlan_dev_hash",
	    VLAN_HASHSZ, mod_hash_null_valdtor, sizeof (dev_t));

	rw_init(&i_dls_vlan_lock, NULL, RW_DEFAULT, NULL);
	i_dls_vlan_count = 0;
}

int
dls_vlan_fini(void)
{
	if (i_dls_vlan_count > 0)
		return (EBUSY);

	/*
	 * Destroy the hash table
	 */
	mod_hash_destroy_hash(i_dls_vlan_hash);
	mod_hash_destroy_hash(i_dls_vlan_dev_hash);
	rw_destroy(&i_dls_vlan_lock);

	/*
	 * Destroy the kmem_cache.
	 */
	kmem_cache_destroy(i_dls_vlan_cachep);
	return (0);
}

/*
 * Exported functions.
 */

/*
 * If vid is VLAN_ID_NONE, then the minor_t to access this dls_vlan_t is
 * ppa + 1, otherwise, we need to allocate the minor_t in this function.
 *
 * If ppa is greater than DLS_MAX_PPA, it means that we do not need to create
 * the VLAN minor node for this MAC, as this MAC is (a) a legacy device, (b)
 * an aggr created without the "key" argument, or (c) a new type of link
 * whose ppa is allocated by mac_minor_hold() in mac_register().
 */
int
dls_vlan_create(const char *macname, uint16_t vid, boolean_t force)
{
	char		node[MAXPATHLEN];
	char		spa[MAXSPALEN];
	char		*driver;
	dls_link_t	*dlp;
	dls_vlan_t	*dvp;
	minor_t		minor = 0;
	mac_handle_t	mh;
	int		ppa;
	dev_info_t	*dip;
	uint32_t	margin = VLAN_TAGSZ;
	int		err = 0;

	if ((err = mac_open(macname, &mh)) != 0)
		return (err);

	/*
	 * First check whether VLANs are able to be created on this MAC.
	 */
	if (vid != VLAN_ID_NONE) {
		if ((mac_info(mh)->mi_media != DL_ETHER) ||
		    (mac_info(mh)->mi_nativemedia != DL_ETHER)) {
			mac_close(mh);
			return (EINVAL);
		}
		if (!force &&
		    ((err = mac_margin_add(mh, &margin, B_FALSE)) != 0)) {
			mac_close(mh);
			return (err);
		}
	}

	/*
	 * Get a reference to a dls_link_t representing the MAC. This call
	 * will create one if necessary.
	 */
	if ((err = dls_link_hold(macname, &dlp)) != 0) {
		if (vid != VLAN_ID_NONE && !force)
			VERIFY(mac_margin_remove(mh, margin) == 0);
		mac_close(mh);
		return (err);
	}

	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	/*
	 * Try to find this VLAN in i_dls_vlan_hash first. The spa
	 * is in the <macname/vid> form.
	 */
	(void) snprintf(spa, MAXSPALEN, "%s/%d", macname, vid);
	if ((err = mod_hash_find(i_dls_vlan_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t)&dvp)) == 0) {
		err = EEXIST;
		goto fail;
	}

	ppa = mac_minor(mh) - 1;
	dip = mac_devinfo_get(mh);

	if (vid == VLAN_ID_NONE) {
		/*
		 * Derives minor number directly from non-VLAN link's PPA.
		 */
		minor = ppa + 1;
	} else if ((minor = mac_minor_hold(B_TRUE)) == 0) {
		/*
		 * Allocate minor number from minor_arenap for VLANs.
		 */
		err = ENOMEM;
		goto fail;
	}

	/*
	 * First create its minor node for non-legacy links, including VLANs
	 * and non-VLANs. This is for /dev nodes backward compatibility.
	 */
	if (vid != VLAN_ID_NONE && ppa < MAC_MAX_MINOR) {

		driver = (char *)ddi_driver_name(dip);

		/* Create a style-1 DLPI device */
		(void) snprintf(node, MAXPATHLEN, "%s%d", driver,
		    vid * 1000 + ppa);
		if (ddi_create_minor_node(dip, node, S_IFCHR, minor,
		    DDI_NT_NET, 0) != DDI_SUCCESS) {
			err = EINVAL;
			goto fail;
		}
	}

	dvp = kmem_cache_alloc(i_dls_vlan_cachep, KM_SLEEP);
	dvp->dv_id = vid;
	dvp->dv_dlp = dlp;
	dvp->dv_dev = makedevice(ddi_driver_major(dip), minor);
	dvp->dv_dip = dip;
	dvp->dv_ppa = ppa;
	dvp->dv_force = force;
	dvp->dv_ref = 0;
	dvp->dv_zone_ref = 0;
	dvp->dv_zid = GLOBAL_ZONEID;
	(void) strlcpy(dvp->dv_spa, spa, MAXSPALEN);
	dls_mac_stat_create(dvp);

	err = mod_hash_insert(i_dls_vlan_hash,
	    (mod_hash_key_t)dvp->dv_spa, (mod_hash_val_t)dvp);
	ASSERT(err == 0);

	err = mod_hash_insert(i_dls_vlan_dev_hash,
	    (mod_hash_key_t)dvp->dv_dev, (mod_hash_val_t)dvp);
	ASSERT(err == 0);

	i_dls_vlan_count++;
	rw_exit(&i_dls_vlan_lock);

	/*
	 * Hold the underlying MAC for VLANs to keep the margin request.
	 * We cannot hold the mac for non-VLANs, because a reference would
	 * prevent the device from detaching.
	 */
	if (vid != VLAN_ID_NONE)
		VERIFY(dls_mac_hold(dvp->dv_dlp) == 0);

	mac_close(mh);
	return (0);

fail:
	rw_exit(&i_dls_vlan_lock);
	if (vid != VLAN_ID_NONE && minor != 0)
		mac_minor_rele(minor);
	dls_link_rele(dlp);
	if (vid != VLAN_ID_NONE && !force)
		VERIFY(mac_margin_remove(mh, margin) == 0);
	mac_close(mh);
	return (err);
}

int
dls_vlan_destroy(const char *macname, uint16_t vid)
{
	char		spa[MAXSPALEN];
	dls_vlan_t	*dvp;
	mod_hash_val_t	val;
	int		err;

	/*
	 * Try to find this VLAN in i_dls_vlan_hash first. The spa
	 * is in the <macname/vid> form.
	 */
	(void) snprintf(spa, MAXSPALEN, "%s/%d", macname, vid);

	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	if ((err = mod_hash_find(i_dls_vlan_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t)&dvp)) != 0) {
		rw_exit(&i_dls_vlan_lock);
		return (ENOENT);
	}

	/*
	 * Check to see if it is referenced by any dls_impl_t.
	 */
	if (dvp->dv_ref != 0) {
		rw_exit(&i_dls_vlan_lock);
		return (EBUSY);
	}

	ASSERT(dvp->dv_zone_ref == 0);

	/*
	 * Remove and destroy the hash table entry.
	 */
	err = mod_hash_remove(i_dls_vlan_hash,
	    (mod_hash_key_t)dvp->dv_spa, (mod_hash_val_t *)&val);
	ASSERT(err == 0);
	ASSERT(dvp == (dls_vlan_t *)val);

	err = mod_hash_remove(i_dls_vlan_dev_hash,
	    (mod_hash_key_t)dvp->dv_dev, (mod_hash_val_t *)&val);
	ASSERT(err == 0);
	ASSERT(dvp == (dls_vlan_t *)val);

	if (vid != VLAN_ID_NONE && dvp->dv_ppa < MAC_MAX_MINOR) {
		char		node[MAXPATHLEN];
		char		*driver;

		/*
		 * Remove the minor nodes for this link.
		 */
		driver = (char *)ddi_driver_name(dvp->dv_dip);
		(void) snprintf(node, MAXPATHLEN, "%s%d", driver,
		    vid * 1000 + dvp->dv_ppa);
		ddi_remove_minor_node(dvp->dv_dip, node);
	}

	dls_mac_stat_destroy(dvp);

	ASSERT(i_dls_vlan_count > 0);
	i_dls_vlan_count--;
	rw_exit(&i_dls_vlan_lock);

	if (vid != VLAN_ID_NONE) {
		if (!dvp->dv_force) {
			(void) mac_margin_remove(dvp->dv_dlp->dl_mh,
			    VLAN_TAGSZ);
		}
		dls_mac_rele(dvp->dv_dlp);
	}

	/*
	 * Release minor to dls_minor_arenap for VLANs
	 */
	if (vid != VLAN_ID_NONE)
		mac_minor_rele(getminor(dvp->dv_dev));

	/*
	 * Release the dls_link_t. This will destroy the dls_link_t and
	 * release the MAC if there are no more dls_vlan_t.
	 */
	dls_link_rele(dvp->dv_dlp);
	kmem_cache_free(i_dls_vlan_cachep, dvp);
	return (0);
}

int
dls_vlan_hold(const char *macname, uint16_t vid, dls_vlan_t **dvpp,
    boolean_t force, boolean_t create_vlan)
{
	char		spa[MAXSPALEN];
	dls_vlan_t	*dvp;
	boolean_t	vlan_created;
	int		err = 0;

	(void) snprintf(spa, MAXSPALEN, "%s/%d", macname, vid);

again:
	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_vlan_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t)&dvp)) != 0) {

		ASSERT(err == MH_ERR_NOTFOUND);

		vlan_created = B_FALSE;
		if (!create_vlan || vid == VLAN_ID_NONE) {
			rw_exit(&i_dls_vlan_lock);
			return (ENOENT);
		}
		rw_exit(&i_dls_vlan_lock);

		err = dls_vlan_create(macname, vid, force);
		if ((err != 0) && (err != EEXIST))
			return (err);

		/*
		 * At this point someone else could do a dls_vlan_hold and
		 * dls_vlan_rele on this new vlan and causes it to be
		 * destroyed. This will at worst cause us to spin a few
		 * times.
		 */
		vlan_created = (err != EEXIST);
		goto again;
	}

	dvp->dv_ref++;
	rw_exit(&i_dls_vlan_lock);

	if ((err = dls_mac_hold(dvp->dv_dlp)) != 0) {
		rw_enter(&i_dls_vlan_lock, RW_WRITER);
		dvp->dv_ref--;
		rw_exit(&i_dls_vlan_lock);
		if (vlan_created)
			(void) dls_vlan_destroy(macname, vid);
		return (err);
	}

	*dvpp = dvp;
	return (0);
}

int
dls_vlan_hold_by_dev(dev_t dev, dls_vlan_t **dvpp)
{
	dls_vlan_t	*dvp;
	int		err;

	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_vlan_dev_hash, (mod_hash_key_t)dev,
	    (mod_hash_val_t *)&dvp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_vlan_lock);
		return (ENOENT);
	}

	dvp->dv_ref++;
	rw_exit(&i_dls_vlan_lock);

	if ((err = dls_mac_hold(dvp->dv_dlp)) != 0) {
		rw_enter(&i_dls_vlan_lock, RW_WRITER);
		dvp->dv_ref--;
		rw_exit(&i_dls_vlan_lock);
		return (err);
	}

	*dvpp = dvp;
	return (0);
}

/*
 * Free the dvp if this is a VLAN and this is the last reference.
 */
void
dls_vlan_rele(dls_vlan_t *dvp)
{
	char		macname[MAXNAMELEN];
	uint16_t	vid;
	boolean_t	destroy_vlan = B_FALSE;

	dls_mac_rele(dvp->dv_dlp);

	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	if (--dvp->dv_ref != 0) {
		rw_exit(&i_dls_vlan_lock);
		return;
	}

	if (dvp->dv_id != VLAN_ID_NONE) {
		destroy_vlan = B_TRUE;
		(void) strncpy(macname, dvp->dv_dlp->dl_name, MAXNAMELEN);
		vid = dvp->dv_id;
	}
	rw_exit(&i_dls_vlan_lock);

	if (destroy_vlan)
		(void) dls_vlan_destroy(macname, vid);
}

int
dls_vlan_setzid(const char *mac, uint16_t vid, zoneid_t zid)
{
	dls_vlan_t	*dvp;
	int		err;
	zoneid_t	old_zid;

	if ((err = dls_vlan_hold(mac, vid, &dvp, B_FALSE, B_TRUE)) != 0)
		return (err);

	mutex_enter(&dvp->dv_lock);
	if ((old_zid = dvp->dv_zid) == zid) {
		mutex_exit(&dvp->dv_lock);
		goto done;
	}

	/*
	 * Check whether this dvp is used by its own zones, if yes,
	 * we cannot change its zoneid.
	 */
	if (dvp->dv_zone_ref != 0) {
		mutex_exit(&dvp->dv_lock);
		err = EBUSY;
		goto done;
	}

	if (zid == GLOBAL_ZONEID) {
		/*
		 * Move the link from the local zone to the global zone,
		 * and release the reference to this link.  At the same time
		 * reset the link's active state so that an aggregation is
		 * allowed to be created over it.
		 */
		dvp->dv_zid = zid;
		mutex_exit(&dvp->dv_lock);
		dls_mac_active_clear(dvp->dv_dlp);
		dls_vlan_rele(dvp);
		goto done;
	} else if (old_zid == GLOBAL_ZONEID) {
		/*
		 * Move the link from the global zone to the local zone,
		 * and hold a reference to this link.  Also, set the link
		 * to the "active" state so that the global zone is
		 * not able to create an aggregation over this link.
		 * TODO: revisit once we allow creating aggregations
		 * within a local zone.
		 */
		if (!dls_mac_active_set(dvp->dv_dlp)) {
			mutex_exit(&dvp->dv_lock);
			err = EBUSY;
			goto done;
		}
		dvp->dv_zid = zid;
		mutex_exit(&dvp->dv_lock);
		return (0);
	} else {
		/*
		 * Move the link from a local zone to another local zone.
		 */
		dvp->dv_zid = zid;
		mutex_exit(&dvp->dv_lock);
	}

done:
	dls_vlan_rele(dvp);
	return (err);
}

/*
 * Find dev_info_t based on the minor node of the link.
 */
dev_info_t *
dls_finddevinfo(dev_t dev)
{
	dls_vlan_t	*dvp;
	dev_info_t	*dip;

	if (dls_vlan_hold_by_dev(dev, &dvp) != 0)
		return (NULL);

	dip = dvp->dv_dip;
	dls_vlan_rele(dvp);
	return (dip);
}
