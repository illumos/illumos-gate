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
 * Data-Link Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/mkdev.h>
#include <sys/modhash.h>
#include <sys/kstat.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/ctype.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>
#include <sys/dld.h>

static kmem_cache_t	*i_dls_vlan_cachep;
static mod_hash_t	*i_dls_vlan_hash;
static mod_hash_t	*i_dls_vlan_dev_hash;
static krwlock_t	i_dls_vlan_lock;
static uint_t		i_dls_vlan_count;

static vmem_t		*minor_arenap;
#define	MINOR_TO_PTR(minor)	((void *)(uintptr_t)(minor))
#define	PTR_TO_MINOR(ptr)	((minor_t)(uintptr_t)(ptr))

#define	VLAN_HASHSZ	67	/* prime */

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_dls_vlan_constructor(void *buf, void *arg, int kmflag)
{
	bzero(buf, sizeof (dls_vlan_t));

	return (0);
}

/*ARGSUSED*/
static void
i_dls_vlan_destructor(void *buf, void *arg)
{
	dls_vlan_t	*dvp = (dls_vlan_t *)buf;

	ASSERT(dvp->dv_ref == 0);
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
	 * Create a hash table, keyed by name, of dls_vlan_t.
	 */
	i_dls_vlan_hash = mod_hash_create_extended("dls_vlan_hash",
	    VLAN_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
	/*
	 * Create a second hash table, keyed by minor, of dls_vlan_t.
	 * The number of the hash slots is the same.
	 */
	i_dls_vlan_dev_hash = mod_hash_create_idhash("dls_vlan_dev_hash",
	    VLAN_HASHSZ, mod_hash_null_valdtor);
	rw_init(&i_dls_vlan_lock, NULL, RW_DEFAULT, NULL);
	i_dls_vlan_count = 0;

	/*
	 * Allocate a vmem arena to manage minor numbers. The range of the
	 * arena will be from DLD_MAX_MINOR + 1 to MAXMIN (maximum legal
	 * minor number).
	 */
	minor_arenap = vmem_create("dls_minor_arena",
	    MINOR_TO_PTR(DLD_MAX_MINOR + 1), MAXMIN, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);
	ASSERT(minor_arenap != NULL);
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

	vmem_destroy(minor_arenap);
	return (0);
}

/*
 * Exported functions.
 */

int
dls_vlan_create(const char *vlanname, const char *macname, uint16_t vid)
{
	dls_link_t	*dlp;
	dls_vlan_t	*dvp;
	int		err;
	uint_t		len;

	/*
	 * Check to see the name is legal. It must be less than IFNAMSIZ
	 * characters in length and must terminate with a digit (before the
	 * NUL, of course).
	 */
	len = strlen(vlanname);
	if (len == 0 || len >= IFNAMSIZ)
		return (EINVAL);

	if (!isdigit(vlanname[len - 1]))
		return (EINVAL);

	/*
	 * Get a reference to a dls_link_t representing the MAC. This call
	 * will create one if necessary.
	 */
	if ((err = dls_link_hold(macname, &dlp)) != 0)
		return (err);

	/*
	 * Allocate a new dls_vlan_t.
	 */
	dvp = kmem_cache_alloc(i_dls_vlan_cachep, KM_SLEEP);
	(void) strlcpy(dvp->dv_name, vlanname, sizeof (dvp->dv_name));
	dvp->dv_id = vid;
	dvp->dv_dlp = dlp;

	/*
	 * Insert the entry into the table.
	 */
	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	if ((err = mod_hash_insert(i_dls_vlan_hash,
	    (mod_hash_key_t)dvp->dv_name, (mod_hash_val_t)dvp)) != 0) {
		kmem_cache_free(i_dls_vlan_cachep, dvp);
		dls_link_rele(dlp);
		err = EEXIST;
		goto done;
	}
	i_dls_vlan_count++;

done:
	rw_exit(&i_dls_vlan_lock);
	return (err);
}

int
dls_vlan_destroy(const char *name)
{
	int		err;
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;
	mod_hash_val_t	val;

	/*
	 * Find the dls_vlan_t in the global hash table.
	 */
	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	err = mod_hash_find(i_dls_vlan_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dvp);
	if (err != 0) {
		err = ENOENT;
		goto done;
	}

	/*
	 * Check to see if it is referenced by any dls_impl_t.
	 */
	if (dvp->dv_ref != 0) {
		err = EBUSY;
		goto done;
	}

	/*
	 * Remove and destroy the hash table entry.
	 */
	err = mod_hash_remove(i_dls_vlan_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&val);
	ASSERT(err == 0);
	ASSERT(dvp == (dls_vlan_t *)val);

	ASSERT(i_dls_vlan_count > 0);
	i_dls_vlan_count--;

	/*
	 * Save a reference to dv_dlp before freeing the dls_vlan_t back
	 * to the cache.
	 */
	dlp = dvp->dv_dlp;
	kmem_cache_free(i_dls_vlan_cachep, dvp);

	/*
	 * Release the dls_link_t. This will destroy the dls_link_t and
	 * release the MAC if there are no more dls_vlan_t.
	 */
	dls_link_rele(dlp);
done:
	rw_exit(&i_dls_vlan_lock);
	return (err);
}

int
dls_vlan_hold(const char *name, dls_vlan_t **dvpp, boolean_t create_vlan)
{
	int		err;
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;
	boolean_t	vlan_created = B_FALSE;
	uint16_t	vid;
	uint_t		mac_ppa;

again:
	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	err = mod_hash_find(i_dls_vlan_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dvp);
	if (err != 0) {
		char		mac[MAXNAMELEN];
		uint_t		index, len;

		ASSERT(err == MH_ERR_NOTFOUND);

		vlan_created = B_FALSE;
		if (!create_vlan) {
			err = ENOENT;
			goto done;
		}

		/*
		 * Only create tagged vlans on demand.
		 * Note that if we get here, 'name' must be a sane
		 * value because it must have been derived from
		 * ddi_major_to_name().
		 */
		if (ddi_parse(name, mac, &index) != DDI_SUCCESS ||
		    (vid = DLS_PPA2VID(index)) == VLAN_ID_NONE ||
		    vid > VLAN_ID_MAX) {
			err = EINVAL;
			goto done;
		}

		mac_ppa = (uint_t)DLS_PPA2INST(index);

		len = strlen(mac);
		ASSERT(len < MAXNAMELEN);
		(void) snprintf(mac + len, MAXNAMELEN - len, "%d", mac_ppa);
		rw_exit(&i_dls_vlan_lock);

		if ((err = dls_vlan_create(name, mac, vid)) != 0) {
			rw_enter(&i_dls_vlan_lock, RW_WRITER);
			goto done;
		}

		/*
		 * At this point someone else could do a dls_vlan_hold and
		 * dls_vlan_rele on this new vlan and causes it to be
		 * destroyed. This will at worst cause us to spin a few
		 * times.
		 */
		vlan_created = B_TRUE;
		goto again;
	}

	dlp = dvp->dv_dlp;

	if ((err = dls_mac_hold(dlp)) != 0)
		goto done;

	/* Create a minor node for this VLAN */
	if (vid != 0 && vlan_created) {
		/* A tagged VLAN */
		dvp->dv_minor = dls_minor_hold(B_TRUE);
		dvp->dv_ppa = DLS_VIDINST2PPA(vid, mac_ppa);

		err = mod_hash_insert(i_dls_vlan_dev_hash,
		    (mod_hash_key_t)(uintptr_t)dvp->dv_minor,
		    (mod_hash_val_t)dvp);
		ASSERT(err == 0);

		err = mac_vlan_create(dlp->dl_mh, name, dvp->dv_minor);

		if (err != 0) {
			mod_hash_val_t	val;

			err = mod_hash_remove(i_dls_vlan_dev_hash,
			    (mod_hash_key_t)(uintptr_t)dvp->dv_minor,
			    (mod_hash_val_t *)&val);
			ASSERT(err == 0);
			ASSERT(dvp == (dls_vlan_t *)val);

			dvp->dv_minor = 0;
			dls_mac_rele(dlp);
			goto done;
		}
	}

	/*
	 * Do not allow the creation of tagged VLAN interfaces on
	 * non-Ethernet links.  Note that we cannot do this check in
	 * dls_vlan_create() nor in this function prior to the call to
	 * dls_mac_hold().  The reason is that before we do a
	 * dls_mac_hold(), we may not have opened the mac, and therefore do
	 * not know what kind of media the mac represents.  In other words,
	 * dls_mac_hold() assigns the dl_mip of the dls_link_t we're
	 * interested in.
	 */
	if (dvp->dv_id != VLAN_ID_NONE &&
	    (dlp->dl_mip->mi_media != DL_ETHER ||
	    dlp->dl_mip->mi_nativemedia != DL_ETHER)) {
		dls_mac_rele(dlp);
		err = EINVAL;
		goto done;
	}

	if ((err = mac_start(dlp->dl_mh)) != 0) {
		dls_mac_rele(dlp);
		goto done;
	}

	if (dvp->dv_ref++ == 0)
		dls_mac_stat_create(dvp);

	*dvpp = dvp;
done:
	rw_exit(&i_dls_vlan_lock);

	/*
	 * We could be destroying a vlan created by another thread. This
	 * is ok because this other thread will just loop back up and
	 * recreate the vlan.
	 */
	if (err != 0 && vlan_created)
		(void) dls_vlan_destroy(name);
	return (err);
}

void
dls_vlan_rele(dls_vlan_t *dvp)
{
	dls_link_t	*dlp;
	char		name[IFNAMSIZ];
	boolean_t	destroy_vlan = B_FALSE;

	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	dlp = dvp->dv_dlp;

	/* a minor node has been created for this vlan */
	if (dvp->dv_ref == 1 && dvp->dv_minor > 0) {
		int err;
		mod_hash_val_t val;

		mac_vlan_remove(dlp->dl_mh, dvp->dv_name);
		err = mod_hash_remove(i_dls_vlan_dev_hash,
		    (mod_hash_key_t)(uintptr_t)dvp->dv_minor,
		    (mod_hash_val_t *)&val);
		ASSERT(err == 0);
		ASSERT(dvp == (dls_vlan_t *)val);
		dls_minor_rele(dvp->dv_minor);
		dvp->dv_minor = 0;
	}

	mac_stop(dlp->dl_mh);
	dls_mac_rele(dlp);
	if (--dvp->dv_ref == 0) {
		dls_mac_stat_destroy(dvp);
		/*
		 * Tagged vlans get destroyed when dv_ref drops
		 * to 0. We need to copy dv_name here because
		 * dvp could disappear after we drop i_dls_vlan_lock.
		 */
		if (dvp->dv_id != 0) {
			(void) strlcpy(name, dvp->dv_name, IFNAMSIZ);
			destroy_vlan = B_TRUE;
		}
	}
	rw_exit(&i_dls_vlan_lock);
	if (destroy_vlan)
		(void) dls_vlan_destroy(name);
}

typedef struct dls_vlan_walk_state {
	int	(*fn)(dls_vlan_t *, void *);
	void	*arg;
	int	rc;
} dls_vlan_walk_state_t;

/*ARGSUSED*/
static uint_t
dls_vlan_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	dls_vlan_walk_state_t	*statep = arg;
	dls_vlan_t		*dvp;

	dvp = (dls_vlan_t *)val;
	statep->rc = statep->fn(dvp, statep->arg);

	return ((statep->rc == 0) ? MH_WALK_CONTINUE : MH_WALK_TERMINATE);
}

int
dls_vlan_walk(int (*fn)(dls_vlan_t *, void *), void *arg)
{
	dls_vlan_walk_state_t	state;

	rw_enter(&i_dls_vlan_lock, RW_READER);

	state.fn = fn;
	state.arg = arg;
	state.rc = 0;
	mod_hash_walk(i_dls_vlan_hash, dls_vlan_walker, (void *)&state);

	rw_exit(&i_dls_vlan_lock);
	return (state.rc);
}

int
dls_vlan_ppa_from_minor(minor_t minor, t_uscalar_t *ppa)
{
	dls_vlan_t	*dvp;

	if (minor <= DLD_MAX_MINOR) {
		*ppa = (t_uscalar_t)minor - 1;
		return (0);
	}

	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	if (mod_hash_find(i_dls_vlan_dev_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&dvp) != 0) {
		rw_exit(&i_dls_vlan_lock);
		return (ENOENT);
	}
	*ppa = dvp->dv_ppa;

	rw_exit(&i_dls_vlan_lock);
	return (0);
}

int
dls_vlan_rele_by_name(const char *name)
{
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;
	boolean_t	destroy_vlan = B_FALSE;

	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	if (mod_hash_find(i_dls_vlan_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dvp) != 0) {
		rw_exit(&i_dls_vlan_lock);
		return (ENOENT);
	}

	dlp = dvp->dv_dlp;

	/* a minor node has been created for this vlan */
	if (dvp->dv_ref == 1 && dvp->dv_minor > 0) {
		int err;
		mod_hash_val_t val;

		mac_vlan_remove(dlp->dl_mh, dvp->dv_name);
		err = mod_hash_remove(i_dls_vlan_dev_hash,
		    (mod_hash_key_t)(uintptr_t)dvp->dv_minor,
		    (mod_hash_val_t *)&val);
		ASSERT(err == 0);
		ASSERT(dvp == (dls_vlan_t *)val);
		dls_minor_rele(dvp->dv_minor);
		dvp->dv_minor = 0;
	}

	mac_stop(dlp->dl_mh);
	dls_mac_rele(dlp);
	if (--dvp->dv_ref == 0) {
		dls_mac_stat_destroy(dvp);
		/* Tagged vlans get destroyed when dv_ref drops to 0. */
		if (dvp->dv_id != 0)
			destroy_vlan = B_TRUE;
	}
	rw_exit(&i_dls_vlan_lock);
	if (destroy_vlan)
		(void) dls_vlan_destroy(name);

	return (0);
}

typedef struct dls_vlan_dip_state {
	minor_t		minor;
	dev_info_t	*dip;
} dls_vlan_dip_k_state_t;

static int
dls_vlan_devinfo(dls_vlan_t *dvp, void *arg)
{
	dls_vlan_dip_k_state_t	*statep = arg;

	if (dvp->dv_minor == statep->minor) {
		dls_link_t	*dlp = dvp->dv_dlp;

		if (dls_mac_hold(dlp) != 0)
			return (0);
		statep->dip = mac_devinfo_get(dlp->dl_mh);
		dls_mac_rele(dlp);

		return (1);
	}

	return (0);
}

dev_info_t *
dls_vlan_finddevinfo(dev_t dev)
{
	dls_vlan_dip_k_state_t	vlan_state;

	vlan_state.minor = getminor(dev);
	vlan_state.dip = NULL;

	(void) dls_vlan_walk(dls_vlan_devinfo, &vlan_state);
	return (vlan_state.dip);
}

/*
 * Allocate a new minor number.
 */
minor_t
dls_minor_hold(boolean_t sleep)
{
	/*
	 * Grab a value from the arena.
	 */
	return (PTR_TO_MINOR(vmem_alloc(minor_arenap, 1,
	    (sleep) ? VM_SLEEP : VM_NOSLEEP)));
}

/*
 * Release a previously allocated minor number.
 */
void
dls_minor_rele(minor_t minor)
{
	/*
	 * Return the value to the arena.
	 */
	vmem_free(minor_arenap, MINOR_TO_PTR(minor), 1);
}

int
dls_vlan_setzoneid(char *name, zoneid_t zid, boolean_t docheck)
{
	int 		err;
	dls_vlan_t	*dvp;

	if ((err = dls_vlan_hold(name, &dvp, B_TRUE)) != 0)
		return (err);

	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	if (!docheck) {
		dvp->dv_zid = zid;
	} else {
		dls_impl_t	*dip;

		for (dip = dvp->dv_impl_list; dip != NULL;
		    dip = dip->di_next_impl)
			if (dip->di_zid != zid)
				break;
		if (dip == NULL)
			dvp->dv_zid = zid;
		else
			err = EBUSY;
	}
	rw_exit(&i_dls_vlan_lock);

	dls_vlan_rele(dvp);
	return (err);
}

int
dls_vlan_getzoneid(char *name, zoneid_t *zidp)
{
	int 		err;
	dls_vlan_t	*dvp;

	if ((err = dls_vlan_hold(name, &dvp, B_FALSE)) != 0)
		return (err);

	*zidp = dvp->dv_zid;

	dls_vlan_rele(dvp);

	return (0);
}

void
dls_vlan_add_impl(dls_vlan_t *dvp, dls_impl_t *dip)
{
	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	dip->di_next_impl = dvp->dv_impl_list;
	dvp->dv_impl_list = dip;
	rw_exit(&i_dls_vlan_lock);
}


void
dls_vlan_remove_impl(dls_vlan_t *dvp, dls_impl_t *dip)
{
	dls_impl_t **pp;
	dls_impl_t *p;

	rw_enter(&i_dls_vlan_lock, RW_WRITER);
	for (pp = &dvp->dv_impl_list; (p =  *pp) != NULL;
	    pp = &(p->di_next_impl))
		if (p == dip)
			break;
	ASSERT(p != NULL);
	*pp = p->di_next_impl;
	p->di_next_impl = NULL;
	rw_exit(&i_dls_vlan_lock);
}
