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
 * Data-Link Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/modhash.h>
#include <sys/kstat.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/ctype.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

static kmem_cache_t	*i_dls_vlan_cachep;
static mod_hash_t	*i_dls_vlan_hash;
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

int
dls_vlan_create(const char *name, const char *dev, uint_t port, uint16_t vid)
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
	len = strlen(name);
	if (len == 0 || len >= IFNAMSIZ)
		return (EINVAL);

	if (!isdigit(name[len - 1]))
		return (EINVAL);

	/*
	 * Get a reference to a dls_link_t representing the MAC. This call
	 * will create one if necessary.
	 */
	if ((err = dls_link_hold(dev, port, &dlp)) != 0)
		return (err);

	/*
	 * Allocate a new dls_vlan_t.
	 */
	dvp = kmem_cache_alloc(i_dls_vlan_cachep, KM_SLEEP);
	(void) strlcpy(dvp->dv_name, name, IFNAMSIZ);
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

again:
	rw_enter(&i_dls_vlan_lock, RW_WRITER);

	err = mod_hash_find(i_dls_vlan_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dvp);
	if (err != 0) {
		char		drv[MAXNAMELEN];
		uint_t		index, port, len;
		uint16_t	vid;

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
		if (ddi_parse(name, drv, &index) != DDI_SUCCESS ||
		    (vid = DLS_PPA2VID(index)) == VLAN_ID_NONE ||
		    vid > VLAN_ID_MAX) {
			err = EINVAL;
			goto done;
		}

		if (strcmp(drv, "aggr") == 0) {
			port = (uint_t)DLS_PPA2INST(index);
			(void) strlcpy(drv, "aggr0", MAXNAMELEN);
		} else {
			port = 0;
			len = strlen(drv);
			ASSERT(len < MAXNAMELEN);
			(void) snprintf(drv + len, MAXNAMELEN - len, "%d",
			    DLS_PPA2INST(index));
		}
		rw_exit(&i_dls_vlan_lock);

		if ((err = dls_vlan_create(name, drv, port, vid)) != 0) {
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
