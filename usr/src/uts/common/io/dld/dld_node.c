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
#include	<sys/conf.h>
#include	<sys/stat.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/ght.h>
#include	<sys/atomic.h>
#include	<sys/fs/dv_node.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>

static int		node_constructor(void *, void *, int);
static void		node_destructor(void *, void *);
static dld_node_t	*node_create(const char *, t_uscalar_t);
static void		node_destroy(dld_node_t *);
static int		node_insert(dld_node_t *);
static void		node_remove(dld_node_t *);
static dld_node_t	*node_find_byminor(minor_t);
static dld_node_t	*node_find_byname(const char *);

static kmem_cache_t	*node_cachep;
static ght_t		node_byminor_hash;
static ght_t		node_byname_hash;

#define	NODE_HASHSZ	67	/* prime value */

/*
 * Initialize this module's data structures.
 */
void
dld_node_init(void)
{
	int	err;

	/*
	 * Create a cache of dld_node_t structures.
	 */
	node_cachep = kmem_cache_create("dld_node_cache", sizeof (dld_node_t),
	    0, node_constructor, node_destructor, NULL, NULL, NULL, 0);
	ASSERT(node_cachep != NULL);

	/*
	 * Create a scalar hash to be keyed by minor number.
	 */
	err = ght_scalar_create("dld_node_byminor_hash", NODE_HASHSZ,
	    &node_byminor_hash);
	ASSERT(err == 0);

	/*
	 * Create a string hash to be keyed by name.
	 */
	err = ght_str_create("dld_node_byname_hash", NODE_HASHSZ,
	    &node_byname_hash);
	ASSERT(err == 0);
}

/*
 * Tear down this module's data structures.
 */
int
dld_node_fini(void)
{
	int	err;

	/*
	 * Check to make sure that the hash tables are empty.
	 */
	ASSERT(ght_count(node_byname_hash) == ght_count(node_byminor_hash));
	if (ght_count(node_byname_hash) != 0)
		return (EBUSY);

	err = ght_destroy(node_byname_hash);
	ASSERT(err == 0);

	err = ght_destroy(node_byminor_hash);
	ASSERT(err == 0);

	kmem_cache_destroy(node_cachep);
	return (0);
}

/*
 * Find an existing node of the given style or create one if none is found.
 * Bump a reference count on the node to note that fact that a reference to
 * it is now held.
 */
dld_node_t *
dld_node_hold(const char *name, t_uscalar_t style)
{
	dld_node_t	*dnp;
	int		err;

	ght_lock(node_byname_hash, GHT_WRITE);
	if ((dnp = node_find_byname(name)) == NULL) {

		if ((dnp = node_create(name, style)) == NULL) {
			ght_unlock(node_byname_hash);
			return (NULL);
		}

		ght_lock(node_byminor_hash, GHT_WRITE);
		err = node_insert(dnp);
		ght_unlock(node_byminor_hash);

		if (err != 0) {
			node_destroy(dnp);
			ght_unlock(node_byname_hash);
			return (NULL);
		}
	} else {
		/*
		 * Make sure it's the right style.
		 */
		if (dnp->dn_style != style) {
			ght_unlock(node_byname_hash);
			return (NULL);
		}
	}

	dnp->dn_ref++;
	ght_unlock(node_byname_hash);
	return (dnp);
}

/*
 * Look up a node by minor number. No reference count is bumped in this case
 * because of the transient nature of how the reference is used. (See
 * drv_open()).
 */
dld_node_t *
dld_node_find(minor_t minor)
{
	dld_node_t	*dnp;

	ght_lock(node_byminor_hash, GHT_READ);
	dnp = node_find_byminor(minor);
	ght_unlock(node_byminor_hash);

	return (dnp);
}

/*
 * Release a previously held reference to a dld_node_t.
 */
void
dld_node_rele(dld_node_t *dnp)
{
	ght_lock(node_byname_hash, GHT_WRITE);
	if (--dnp->dn_ref == 0) {
		ght_lock(node_byminor_hash, GHT_WRITE);
		node_remove(dnp);
		ght_unlock(node_byminor_hash);
		node_destroy(dnp);
	}
	ght_unlock(node_byname_hash);
}

/*
 * kmem_cache constructor function: see kmem_cache_create(9f).
 */
/*ARGSUSED*/
static int
node_constructor(void *buf, void *cdrarg, int kmflags)
{
	dld_node_t	*dnp = buf;

	bzero(buf, sizeof (dld_node_t));

	/*
	 * Reserve a minor number for this node.
	 */
	if ((dnp->dn_minor = dld_minor_hold(kmflags == KM_SLEEP)) == 0)
		return (-1);

	return (0);
}

/*
 * kmem_cache destructor function.
 */
/*ARGSUSED*/
static void
node_destructor(void *buf, void *cdrarg)
{
	dld_node_t	*dnp = buf;

	/*
	 * Release the minor number.
	 */
	dld_minor_rele(dnp->dn_minor);
}

/*
 * Create a new dld_node_t object.
 */
static dld_node_t *
node_create(const char *name, t_uscalar_t style)
{
	dld_node_t	*dnp;
	char		*buf;
	int		err;
#define	SUFFIX		"_ppa_hash"

	ASSERT(strlen(name) < IFNAMSIZ);
	ASSERT(style == DL_STYLE1 || style == DL_STYLE2);

	dnp = kmem_cache_alloc(node_cachep, KM_SLEEP);

	(void) strlcpy(dnp->dn_name, name, IFNAMSIZ);

	dnp->dn_style = style;

	if (style == DL_STYLE2) {
		/*
		 * For style 2 nodes we need to create a private hash table
		 * to manage the multiple PPAs.
		 */
		size_t	size = strlen(dnp->dn_name) + strlen(SUFFIX) + 1;
		buf = kmem_alloc(size, KM_SLEEP);
		(void) sprintf(buf, "%s" SUFFIX, name);

		err = ght_scalar_create(buf, NODE_HASHSZ, &(dnp->dn_hash));
		ASSERT(err == 0);

		kmem_free(buf, size);
	}

	/*
	 * Create a dev_t in the file system with the given name.
	 */
	if (ddi_create_minor_node(dld_dip, (char *)dnp->dn_name, S_IFCHR,
	    dnp->dn_minor, DDI_NT_NET, 0) != DDI_SUCCESS)
		goto failed;

	return (dnp);

failed:
	node_destroy(dnp);
	return (NULL);

#undef	SUFFIX
}

/*
 * Destroy a dld_node_t object.
 */
static void
node_destroy(dld_node_t *dnp)
{
	int		err;

	ASSERT(dnp->dn_ref == 0);

	if (dnp->dn_style == DL_STYLE2) {
		/*
		 * This was a style 2 node so we must destroy the private
		 * hash table.
		 */
		err = ght_destroy(dnp->dn_hash);
		ASSERT(err == 0);
	}

	/*
	 * Remove the dev_t from the file system.
	 */
	ddi_remove_minor_node(dld_dip, dnp->dn_name);

	/*
	 * Work around an apparent bug in devfs where /devices is not
	 * kept up-to-date.
	 */
	(void) devfs_clean(ddi_get_parent(dld_dip), NULL, 0);

	kmem_cache_free(node_cachep, dnp);
}

/*
 * Insert a node into both global hash tables.
 */
static int
node_insert(dld_node_t *dnp)
{
	ghte_t		byminor_hte;
	ghte_t		byname_hte;
	int		err;

	/*
	 * Allocate a new entry for the 'by minor' hash table.
	 */
	if ((byminor_hte = ght_alloc(node_byminor_hash, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	/*
	 * Fill in the information.
	 */
	GHT_KEY(byminor_hte) = GHT_SCALAR_TO_KEY(dnp->dn_minor);
	GHT_VAL(byminor_hte) = GHT_PTR_TO_VAL(dnp);

	/*
	 * Insert the node into the table.
	 */
	if ((err = ght_insert(byminor_hte)) != 0) {
		ght_free(byminor_hte);
		return (err);
	}

	ASSERT(dnp->dn_byminor_hte == NULL);
	dnp->dn_byminor_hte = byminor_hte;

	/*
	 * Allocate a new node for the 'by name' hash table.
	 */
	if ((byname_hte = ght_alloc(node_byname_hash, KM_NOSLEEP)) == NULL)
		goto failed;

	/*
	 * Fill in the information.
	 */
	GHT_KEY(byname_hte) = GHT_PTR_TO_KEY(dnp->dn_name);
	GHT_VAL(byname_hte) = GHT_PTR_TO_VAL(dnp);

	/*
	 * Insert the node into the table.
	 */
	if ((err = ght_insert(byname_hte)) != 0) {
		ght_free(byname_hte);
		goto failed;
	}

	ASSERT(dnp->dn_byname_hte == NULL);
	dnp->dn_byname_hte = byname_hte;

	return (0);

failed:
	ght_remove(dnp->dn_byminor_hte);
	dnp->dn_byminor_hte = NULL;

	return (err);
}

/*
 * Remove a node from both the global hash tables.
 */
static void
node_remove(dld_node_t *dnp)
{
	/*
	 * Remove the node from the 'by name' hash table and free.
	 */
	ASSERT(dnp->dn_byname_hte != NULL);
	ght_remove(dnp->dn_byname_hte);
	ght_free(dnp->dn_byname_hte);
	dnp->dn_byname_hte = NULL;

	/*
	 * Remove the node from the 'by minor' hash table and free.
	 */
	ASSERT(dnp->dn_byminor_hte != NULL);
	ght_remove(dnp->dn_byminor_hte);
	ght_free(dnp->dn_byminor_hte);
	dnp->dn_byminor_hte = NULL;
}

/*
 * Look up a node in the 'by minor' table.
 */
static dld_node_t *
node_find_byminor(minor_t minor)
{
	ghte_t		hte;

	if (ght_find(node_byminor_hash, GHT_SCALAR_TO_KEY(minor), &hte) != 0)
		return (NULL);

	return ((dld_node_t *)GHT_VAL(hte));
}

/*
 * Look up a node in the 'by name' table.
 */
static dld_node_t *
node_find_byname(const char *name)
{
	ghte_t		hte;

	if (ght_find(node_byname_hash, GHT_PTR_TO_KEY(name), &hte) != 0)
		return (NULL);

	return ((dld_node_t *)GHT_VAL(hte));
}

/*
 * Add a PPA to a node.
 */
int
dld_node_ppa_add(dld_node_t *dnp, t_scalar_t index, dld_ppa_t *dpp)
{
	ghte_t		hte;
	int		err;

	if (dnp->dn_style == DL_STYLE1) {
		/*
		 * Only a single PPA can be added to a style 1 node so we
		 * insist that the index number argument is set to -1.
		 */
		ASSERT(index == -1);

		/*
		 * Check to see if there is an existing PPA.
		 */
		if (dnp->dn_dpp != NULL)
			return (EEXIST);

		dnp->dn_dpp = dpp;
		return (0);
	}
	ASSERT(dnp->dn_style == DL_STYLE2);

	/*
	 * Multiple PPAs can be added to a style 2 node and so we
	 * insist that the index number argument is zero or greater.
	 */
	ASSERT(index >= 0);

	/*
	 * Allocate an entry for the private hash table.
	 */
	hte = ght_alloc(dnp->dn_hash, KM_SLEEP);

	/*
	 * Fill in the information.
	 */
	GHT_KEY(hte) = GHT_SCALAR_TO_KEY(index);
	GHT_VAL(hte) = GHT_PTR_TO_VAL(dpp);

	/*
	 * Lock the table.
	 */
	ght_lock(dnp->dn_hash, GHT_WRITE);

	/*
	 * Insert the node into the table.
	 */
	if ((err = ght_insert(hte)) != 0)
		ght_free(hte);

	/*
	 * Unlock the table.
	 */
	ght_unlock(dnp->dn_hash);
	return (err);
}

/*
 * Remove a PPA from the node.
 */
int
dld_node_ppa_remove(dld_node_t *dnp, t_scalar_t index)
{
	ghte_t		hte;
	int		err;

	if (dnp->dn_style == DL_STYLE1) {
		ASSERT(index == -1);

		if (dnp->dn_dpp == NULL)
			return (ENOENT);

		dnp->dn_dpp = NULL;
		return (0);
	}
	ASSERT(dnp->dn_style == DL_STYLE2);

	ASSERT(index >= 0);

	ght_lock(dnp->dn_hash, GHT_WRITE);
	if ((err = ght_find(dnp->dn_hash, GHT_SCALAR_TO_KEY(index),
	    &hte)) == 0) {
		ght_remove(hte);
		ght_free(hte);
	}
	ght_unlock(dnp->dn_hash);

	return (err);
}

/*
 * Look up a dld_ppa_t from a dld_node_t.
 */
dld_ppa_t *
dld_node_ppa_find(dld_node_t *dnp, t_scalar_t index)
{
	ghte_t		hte;

	if (dnp->dn_style == DL_STYLE1) {
		ASSERT(index == -1);
		return (dnp->dn_dpp);
	}
	ASSERT(dnp->dn_style == DL_STYLE2);

	ASSERT(index >= 0);

	ght_lock(dnp->dn_hash, GHT_READ);
	if (ght_find(dnp->dn_hash, GHT_SCALAR_TO_KEY(index), &hte) != 0) {
		ght_unlock(dnp->dn_hash);
		return (NULL);
	}
	ght_unlock(dnp->dn_hash);

	return ((dld_ppa_t *)GHT_VAL(hte));
}
