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
 * Data-Link Driver
 */

#include	<sys/types.h>
#include	<sys/dlpi.h>
#include	<sys/atomic.h>
#include	<sys/ctype.h>
#include	<sys/ght.h>
#include	<net/if.h>

#include	<sys/dld.h>
#include	<sys/dld_impl.h>

static int		ppa_constructor(void *, void *, int);
static void		ppa_destructor(void *, void *);
static int		ppa_create(const char *, const char *, uint_t, uint16_t,
    dld_ppa_t **);
static int		ppa_destroy(dld_ppa_t *);
static void		ppa_attr(dld_ppa_t *, char *, uint_t *, uint16_t *);

static kmem_cache_t	*ppa_cachep;
static ght_t		ppa_hash;

#define	PPA_HASHSZ	23	/* prime value */

/*
 * Initialize this module's data structures.
 */
void
dld_ppa_init(void)
{
	int	err;

	/*
	 * Create a cache of dld_ppa_t objects.
	 */
	ppa_cachep = kmem_cache_create("dld_ppa_cache", sizeof (dld_ppa_t), 0,
	    ppa_constructor, ppa_destructor, NULL, NULL, NULL, 0);
	ASSERT(ppa_cachep != NULL);

	/*
	 * Create a string hash table to be keyed by name.
	 */
	err = ght_str_create("dld_ppa_hash", PPA_HASHSZ, &ppa_hash);
	ASSERT(err == 0);
}

/*
 * Tear down this module's data structures.
 */
int
dld_ppa_fini(void)
{
	int	err;

	/*
	 * If the hash table cannot be destroyed then it is not empty.
	 */
	if ((err = ght_destroy(ppa_hash)) != 0)
		return (err);

	kmem_cache_destroy(ppa_cachep);
	return (0);
}

/*
 * Create a new dld_ppa_t object.
 */
int
dld_ppa_create(const char *name, const char *dev, uint_t port, uint16_t vid)
{
	dld_ppa_t	*dpp;
	ghte_t		hte;
	int		err;

	ASSERT(strlen(name) < IFNAMSIZ);
	ASSERT(strlen(dev) < MAXNAMELEN);

	/*
	 * Create the object.
	 */
	if ((err = ppa_create(name, dev, port, vid, &dpp)) != 0)
		return (err);

	/*
	 * Allocate an entry for the hash table.
	 */
	hte = ght_alloc(ppa_hash, KM_SLEEP);

	/*
	 * Fill in the information.
	 */
	GHT_KEY(hte) = GHT_PTR_TO_KEY(dpp->dp_name);
	GHT_VAL(hte) = GHT_PTR_TO_VAL(dpp);

	/*
	 * Lock the table.
	 */
	ght_lock(ppa_hash, GHT_WRITE);

	/*
	 * Insert the entry.
	 */
	if ((err = ght_insert(hte)) != 0) {
		ght_free(hte);
		(void) ppa_destroy(dpp);
	}

	/*
	 * Unlock the table.
	 */
	ght_unlock(ppa_hash);
	return (err);
}

/*
 * Destroy a dld_ppa_t object.
 */
int
dld_ppa_destroy(const char *name)
{
	ghte_t		hte;
	int		err;
	dld_ppa_t	*dpp;

	ASSERT(strlen(name) < IFNAMSIZ);

	ght_lock(ppa_hash, GHT_WRITE);
	if ((err = ght_find(ppa_hash, GHT_PTR_TO_KEY(name), &hte)) != 0)
		goto failed;

	dpp = (dld_ppa_t *)GHT_VAL(hte);
	if ((err = ppa_destroy(dpp)) != 0)
		goto failed;

	ght_remove(hte);
	ght_free(hte);

failed:
	ght_unlock(ppa_hash);
	return (err);
}

/*
 * Get the attributes of a dld_ppa_t object.
 */
int
dld_ppa_attr(const char *name, char *dev, uint_t *portp, uint16_t *vidp)
{
	ghte_t		hte;
	int		err;
	dld_ppa_t	*dpp;

	ASSERT(strlen(name) < IFNAMSIZ);

	ght_lock(ppa_hash, GHT_READ);
	if ((err = ght_find(ppa_hash, (ght_key_t)name, &hte)) == 0) {
		dpp = (dld_ppa_t *)GHT_VAL(hte);
		ppa_attr(dpp, dev, portp, vidp);
	}
	ght_unlock(ppa_hash);

	return (err);
}

/*
 * kmem_cache constructor function: see kmem_cache_create(9f).
 */
/*ARGSUSED*/
static int
ppa_constructor(void *buf, void *cdrarg, int kmflags)
{
	dld_ppa_t	*dpp = buf;

	bzero(buf, sizeof (dld_ppa_t));
	dpp->dp_index = -1;

	return (0);
}

/*
 * kmem_cache destructor function
 */
/*ARGSUSED*/
static void
ppa_destructor(void *buf, void *cdrarg)
{
	dld_ppa_t	*dpp = buf;

	ASSERT(dpp->dp_index == -1);
	ASSERT(dpp->dp_style1 == NULL);
	ASSERT(dpp->dp_style2 == NULL);
}

/*
 * Create a new dld_ppa_t.
 */
static int
ppa_create(const char *name, const char *dev, uint_t port, uint16_t vid,
    dld_ppa_t **dppp)
{
	dld_ppa_t	*dpp;
	dld_node_t	*dnp;
	char		provider[IFNAMSIZ];
	uint_t		index;
	int		err;

	/*
	 * All dld_ppa_t must be represented by both style 1 and style 2
	 * providers. Therefore their name must always be of the form
	 * <DLS provider>##<PPA index>.
	 */
	if (ddi_parse(name, provider, &index) != DDI_SUCCESS)
		return (EINVAL);

	/*
	 * Allocate a dld_ppa_t from the cache.
	 */
	dpp = kmem_cache_alloc(ppa_cachep, KM_SLEEP);
	(void) strlcpy(dpp->dp_name, name, IFNAMSIZ);
	(void) strlcpy(dpp->dp_dev, dev, MAXNAMELEN);
	dpp->dp_port = port;
	dpp->dp_vid = vid;

	/*
	 * Create a data-link.
	 */
	if ((err = dls_create(dpp->dp_name, dev, port, vid)) != 0) {
		kmem_cache_free(ppa_cachep, dpp);
		return (err);
	}

	/*
	 * Create a style 1 dld_node_t, unless their use has been disabled.
	 */
	if (!(dld_opt & DLD_OPT_NO_STYLE1)) {
		if ((dnp = dld_node_hold(name, DL_STYLE1)) == NULL) {
			err = ENOENT;
			goto failed;
		}

		/*
		 * Add the dld_ppa_t to the dld_node_t and keep a backwards
		 * reference.
		 */
		if ((err = dld_node_ppa_add(dnp, -1, dpp)) != 0) {
			dld_node_rele(dnp);
			goto failed;
		}

		dpp->dp_style1 = dnp;
	}

	/*
	 * Create, or grab a reference to an existing style 2 dld_node_t.
	 */
	if ((dnp = dld_node_hold(provider, DL_STYLE2)) == NULL) {
		err = ENOENT;
		goto failed;
	}

	/*
	 * Add the dld_ppa_t to the dld_node_t.
	 */
	dpp->dp_index = index;
	if ((err = dld_node_ppa_add(dnp, dpp->dp_index, dpp)) != 0) {
		dld_node_rele(dnp);
		goto failed;
	}

	/*
	 * Keep a backwards reference.
	 */
	dpp->dp_style2 = dnp;

done:
	*dppp = dpp;
	return (0);

failed:
	(void) ppa_destroy(dpp);
	return (err);
}

/*
 * Destroy a dld_ppa_t.
 */
static int
ppa_destroy(dld_ppa_t *dpp)
{
	dld_node_t	*dnp;
	int		err;

	/*
	 * Destroy the data-link.
	 */
	if ((err = dls_destroy(dpp->dp_name)) != 0) {
		ASSERT(err == EBUSY);
		return (EBUSY);
	}

	/*
	 * If the style 2 dld_node_t exists then release it.
	 */
	if ((dnp = dpp->dp_style2) != NULL) {
		ASSERT(dpp->dp_index != -1);

		err = dld_node_ppa_remove(dnp, dpp->dp_index);
		ASSERT(err == 0);
		dpp->dp_index = -1;

		dld_node_rele(dnp);
		dpp->dp_style2 = NULL;
	}
	ASSERT(dpp->dp_index == -1);

	/*
	 * If the style 1 dld_node_t exists then release it.
	 */
	if ((dnp = dpp->dp_style1) != NULL) {
		err = dld_node_ppa_remove(dnp, -1);
		ASSERT(err == 0);

		dld_node_rele(dnp);
		dpp->dp_style1 = NULL;
	}

	/*
	 * Free the object back to the cache.
	 */
	kmem_cache_free(ppa_cachep, dpp);
	return (0);
}

/*
 * Get the attributes of a dld_ppa_t.
 */
static void
ppa_attr(dld_ppa_t *dpp, char *dev, uint_t *portp, uint16_t *vidp)
{
	(void) strlcpy(dev, dpp->dp_dev, MAXNAMELEN);
	*portp = dpp->dp_port;
	*vidp = dpp->dp_vid;
}
