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
#include <sys/ght.h>
#include <sys/kstat.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/ctype.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

static kmem_cache_t	*i_dls_vlan_cachep;
static ght_t		i_dls_vlan_hash;

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
	int	err;

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
	err = ght_str_create("dls_vlan_hash", VLAN_HASHSZ, &i_dls_vlan_hash);
	ASSERT(err == 0);
}

int
dls_vlan_fini(void)
{
	int	err;

	/*
	 * If the hash table is not empty then this call will return EBUSY.
	 */
	if ((err = ght_destroy(i_dls_vlan_hash)) != 0)
		return (err);

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
	ghte_t		hte;
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
	 * If we're creating a tagged VLAN, grab a reference to the MAC.
	 * Strictly speaking, this is only needed for aggregations (so that
	 * they can't be deleted when there are configured VLAN's), but it
	 * doesn't hurt for other MAC's either.
	 */
	if (vid != 0 && (err = dls_mac_hold(dlp)) != 0) {
		dls_link_rele(dlp);
		return (err);
	}

	/*
	 * Allocate a new dls_vlan_t.
	 */
	dvp = kmem_cache_alloc(i_dls_vlan_cachep, KM_SLEEP);
	(void) strlcpy(dvp->dv_name, name, IFNAMSIZ);
	dvp->dv_id = vid;
	dvp->dv_dlp = dlp;

	/*
	 * Allocate a new hash table entry.
	 */
	hte = ght_alloc(i_dls_vlan_hash, KM_SLEEP);

	GHT_KEY(hte) = GHT_PTR_TO_KEY(dvp->dv_name);
	GHT_VAL(hte) = GHT_PTR_TO_VAL(dvp);

	/*
	 * Insert the entry into the table.
	 */
	ght_lock(i_dls_vlan_hash, GHT_WRITE);
	if ((err = ght_insert(hte)) != 0) {
		ght_free(hte);
		kmem_cache_free(i_dls_vlan_cachep, dvp);
		if (vid != 0)
			dls_mac_rele(dlp);
		dls_link_rele(dlp);
		goto done;
	}

	/*
	 * Create kstats.
	 */
	dls_stat_create(dvp);

done:
	ght_unlock(i_dls_vlan_hash);
	return (err);
}

int
dls_vlan_destroy(const char *name)
{
	int		err;
	ghte_t		hte;
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;

	/*
	 * Find the dls_vlan_t in the global hash table.
	 */
	ght_lock(i_dls_vlan_hash, GHT_WRITE);
	if ((err = ght_find(i_dls_vlan_hash, GHT_PTR_TO_KEY(name), &hte)) != 0)
		goto done;

	/*
	 * Check to see if it is referenced by any dls_t.
	 */
	dvp = (dls_vlan_t *)GHT_VAL(hte);
	if (dvp->dv_ref != 0) {
		err = EBUSY;
		goto done;
	}

	/*
	 * Destroy kstats before releasing dls_link_t and before destroying
	 * the dls_vlan_t to ensure ks_update is safe.
	 */
	dls_stat_destroy(dvp);

	/*
	 * Remove and destroy the hash table entry.
	 */
	ght_remove(hte);
	ght_free(hte);

	dlp = dvp->dv_dlp;

	/*
	 * If we're destroying a tagged VLAN, release the hold we acquired
	 * in dls_vlan_create().
	 */
	if (dvp->dv_id != 0)
		dls_mac_rele(dlp);

	/*
	 * Free the dls_vlan_t back to the cache.
	 */
	kmem_cache_free(i_dls_vlan_cachep, dvp);

	/*
	 * Release the dls_link_t. This will destroy the dls_link_t and
	 * release the MAC if there are no more dls_vlan_t.
	 */
	dls_link_rele(dlp);
done:
	ght_unlock(i_dls_vlan_hash);
	return (err);
}

int
dls_vlan_hold(const char *name, dls_vlan_t **dvpp)
{
	int		err;
	ghte_t		hte;
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;

	ght_lock(i_dls_vlan_hash, GHT_WRITE);
	if ((err = ght_find(i_dls_vlan_hash, GHT_PTR_TO_KEY(name), &hte)) != 0)
		goto done;

	dvp = (dls_vlan_t *)GHT_VAL(hte);
	dlp = dvp->dv_dlp;

	if ((err = dls_mac_hold(dlp)) != 0)
		goto done;

	if ((err = mac_start(dlp->dl_mh)) != 0) {
		dls_mac_rele(dlp);
		goto done;
	}

	dvp->dv_ref++;
	*dvpp = dvp;
done:
	ght_unlock(i_dls_vlan_hash);
	return (err);
}

void
dls_vlan_rele(dls_vlan_t *dvp)
{
	dls_link_t	*dlp;

	ght_lock(i_dls_vlan_hash, GHT_WRITE);
	dlp = dvp->dv_dlp;

	mac_stop(dlp->dl_mh);
	dls_mac_rele(dlp);
	--dvp->dv_ref;
	ght_unlock(i_dls_vlan_hash);
}
