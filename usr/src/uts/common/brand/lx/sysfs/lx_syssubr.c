/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * lx_syssubr.c: Various functions for the /sys vnodeops.
 */

#include <sys/varargs.h>

#include <sys/cpuvar.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <sys/prsystm.h>

#include "lx_sysfs.h"

#define	LXSYSCACHE_NAME "lxsys_cache"

static int lxsys_node_constructor(void *, void *, int);
static void lxsys_node_destructor(void *, void *);

static kmem_cache_t *lxsys_node_cache;

void
lxsys_initnodecache()
{
	lxsys_node_cache = kmem_cache_create(LXSYSCACHE_NAME,
	    sizeof (lxsys_node_t), 0,
	    lxsys_node_constructor, lxsys_node_destructor, NULL, NULL, NULL, 0);
}

void
lxsys_fininodecache()
{
	kmem_cache_destroy(lxsys_node_cache);
}

/* ARGSUSED */
static int
lxsys_node_constructor(void *buf, void *un, int kmflags)
{
	lxsys_node_t	*lxsnp = buf;
	vnode_t		*vp;

	vp = lxsnp->lxsys_vnode = vn_alloc(kmflags);
	if (vp == NULL)
		return (-1);

	(void) vn_setops(vp, lxsys_vnodeops);
	vp->v_data = lxsnp;

	return (0);
}

/* ARGSUSED */
static void
lxsys_node_destructor(void *buf, void *un)
{
	lxsys_node_t	*lxsnp = buf;

	vn_free(LXSTOV(lxsnp));
}

/*
 * Calculate an inode number
 *
 * This takes various bits of info and munges them
 * to give the inode number for an lxsys node
 */
ino_t
lxsys_inode(lxsys_nodetype_t type)
{
	return (curproc->p_zone->zone_zsched->p_pid + type);
}

/*
 * Return inode number of parent (directory)
 */
ino_t
lxsys_parentinode(lxsys_node_t *lxsnp)
{
	/*
	 * If the input node is the root then the parent inode
	 * is the mounted on inode so just return our inode number
	 */
	if (lxsnp->lxsys_type != LXSYS_SYSDIR)
		return (VTOLXS(lxsnp->lxsys_parent)->lxsys_ino);
	else
		return (lxsnp->lxsys_ino);
}

/*
 * Allocate a new lxsys node
 *
 * This also allocates the vnode associated with it
 */
lxsys_node_t *
lxsys_getnode(vnode_t *dp, lxsys_nodetype_t type, proc_t *p)
{
	lxsys_node_t *lxsnp;
	vnode_t *vp;
	timestruc_t now;

	/*
	 * Allocate a new node. It is deallocated in vop_innactive
	 */
	lxsnp = kmem_cache_alloc(lxsys_node_cache, KM_SLEEP);

	/*
	 * Set defaults (may be overridden below)
	 */
	gethrestime(&now);
	lxsnp->lxsys_type = type;
	lxsnp->lxsys_realvp = NULL;
	lxsnp->lxsys_parent = dp;
	VN_HOLD(dp);

	/* Pretend files belong to sched */
	lxsnp->lxsys_time = now;
	lxsnp->lxsys_uid = lxsnp->lxsys_gid = 0;
	lxsnp->lxsys_ino = lxsys_inode(type);

	/* initialize the vnode data */
	vp = lxsnp->lxsys_vnode;
	vn_reinit(vp);
	vp->v_flag = VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vp->v_vfsp = dp->v_vfsp;

	/*
	 * Do node specific stuff
	 */
	switch (type) {
	case LXSYS_SYSDIR:
		vp->v_flag |= VROOT;
		vp->v_type = VDIR;
		lxsnp->lxsys_mode = 0555;	/* read-search by all */
		break;


	case LXSYS_FSDIR:
	case LXSYS_FS_CGROUPDIR:
		vp->v_type = VDIR;
		lxsnp->lxsys_mode = 0555;	/* read-search by all */
		break;
	default:
		vp->v_type = VREG;
		lxsnp->lxsys_mode = 0444;	/* read-only by all */
		break;
	}

	return (lxsnp);
}


/*
 * Free the storage obtained from lxsys_getnode().
 */
void
lxsys_freenode(lxsys_node_t *lxsnp)
{
	ASSERT(lxsnp != NULL);
	ASSERT(LXSTOV(lxsnp) != NULL);

	/*
	 * delete any association with realvp
	 */
	if (lxsnp->lxsys_realvp != NULL)
		VN_RELE(lxsnp->lxsys_realvp);

	/*
	 * delete any association with parent vp
	 */
	if (lxsnp->lxsys_parent != NULL)
		VN_RELE(lxsnp->lxsys_parent);

	/*
	 * Release the lxsysnode.
	 */
	kmem_cache_free(lxsys_node_cache, lxsnp);
}
