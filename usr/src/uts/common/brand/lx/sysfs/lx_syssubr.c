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
 * Copyright 2016 Joyent, Inc.
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
lxsys_inode(lxsys_nodetype_t type, unsigned int instance,
    unsigned int endpoint)
{
	/*
	 * Sysfs Inode format:
	 * 0000AABBBBCC
	 *
	 * AA - TYPE
	 * BBBB - INSTANCE
	 * CC - ENDPOINT
	 */
	ASSERT(instance <= 0xffff);
	ASSERT(endpoint <= 0xff);

	return ((ino_t)(type << 24)|(instance << 8)|endpoint);
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
	if (lxsnp->lxsys_type == LXSYS_STATIC &&
	    lxsnp->lxsys_instance == LXSYS_INST_ROOT) {
		return (lxsnp->lxsys_ino);
	} else {
		return (VTOLXS(lxsnp->lxsys_parentvp)->lxsys_ino);
	}
}

/*
 * Allocate a new lxsys node
 *
 * This also allocates the vnode associated with it
 */
lxsys_node_t *
lxsys_getnode(vnode_t *dp, lxsys_nodetype_t type, unsigned int instance,
    unsigned int endpoint)
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
	lxsnp->lxsys_instance = instance;
	lxsnp->lxsys_endpoint = endpoint;
	lxsnp->lxsys_next = NULL;
	lxsnp->lxsys_parentvp = dp;
	VN_HOLD(dp);

	lxsnp->lxsys_time = now;
	lxsnp->lxsys_uid = lxsnp->lxsys_gid = 0;
	lxsnp->lxsys_ino = lxsys_inode(type, instance, endpoint);

	/* initialize the vnode data */
	vp = lxsnp->lxsys_vnode;
	vn_reinit(vp);
	vp->v_flag = VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vp->v_vfsp = dp->v_vfsp;

	/*
	 * Default to a directory with open permissions.
	 * Specific components will override this
	 */
	if (type == LXSYS_STATIC && instance == LXSYS_INST_ROOT) {
		vp->v_flag |= VROOT;
	}
	vp->v_type = VDIR;
	lxsnp->lxsys_mode = 0555;

	return (lxsnp);
}

lxsys_node_t *
lxsys_getnode_static(vnode_t *dp, unsigned int instance)
{
	lxsys_mnt_t *lxsm = VTOLXSM(dp);
	lxsys_node_t *lnp, *tail = NULL;

	mutex_enter(&lxsm->lxsysm_lock);
	for (lnp = lxsm->lxsysm_node; lnp != NULL; lnp = lnp->lxsys_next) {
		if (lnp->lxsys_instance == instance) {
			VERIFY(lnp->lxsys_parentvp == dp);

			VN_HOLD(lnp->lxsys_vnode);
			mutex_exit(&lxsm->lxsysm_lock);
			return (lnp);
		} else if (lnp->lxsys_next == NULL) {
			/* Found no match by the end of the list */
			tail = lnp;
			break;
		}
	}

	tail->lxsys_next = lxsys_getnode(dp, LXSYS_STATIC, instance, 0);
	lnp = tail->lxsys_next;
	/* Allow mounts on static entries */
	LXSTOV(lnp)->v_flag &= (~VNOMOUNT);
	mutex_exit(&lxsm->lxsysm_lock);
	return (lnp);
}

/* Clean up persistence for static lxsys_node */
int
lxsys_freenode_static(lxsys_node_t *lnp)
{
	lxsys_node_t *plnp;
	vnode_t *vp = LXSTOV(lnp);
	lxsys_mnt_t *lxsm = VTOLXSM(vp);

	if (lnp->lxsys_instance == LXSYS_INST_ROOT) {
		/*
		 * The root vnode does not need special cleanup since it
		 * anchors the list and is freed by lxsys_unmount.
		 */
		return (0);
	}

	mutex_enter(&lxsm->lxsysm_lock);

	/*
	 * It is possible that a different process acquired a fresh reference
	 * to this vnode via lookup while we were waiting on the lxsysm_lock.
	 * To avoid freeing the vnode out from under them, we will double-check
	 * v_count and bail from the fop_inactive if it was grabbed.
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_count != 1) {
		VERIFY(vp->v_count > 0);

		/* Release our hold before bailing out of lxsys_inactive */
		vp->v_count--;

		mutex_exit(&vp->v_lock);
		mutex_exit(&lxsm->lxsysm_lock);
		return (-1);
	}
	mutex_exit(&vp->v_lock);

	/* search for the record pointing to lnp */
	plnp = lxsm->lxsysm_node;
	while (plnp != NULL && plnp->lxsys_next != lnp) {
		plnp = plnp->lxsys_next;
	}
	/* entry should always be found */
	VERIFY(plnp != NULL);
	plnp->lxsys_next = lnp->lxsys_next;

	mutex_exit(&lxsm->lxsysm_lock);
	return (0);
}

/*
 * Free the storage obtained from lxsys_getnode().
 */
void
lxsys_freenode(lxsys_node_t *lxsnp)
{
	vnode_t *vp = LXSTOV(lxsnp);

	VERIFY(vp != NULL);

	if (lxsnp->lxsys_type == LXSYS_STATIC) {
		if (lxsys_freenode_static(lxsnp) != 0) {
			return;
		}
	}

	/*
	 * delete any association with parent vp
	 */
	if (lxsnp->lxsys_parentvp != NULL)
		VN_RELE(lxsnp->lxsys_parentvp);

	/*
	 * Release the lxsysnode.
	 */
	kmem_cache_free(lxsys_node_cache, lxsnp);
}

/*
 * Get the netstack associated with this lxsys mount
 */
netstack_t *
lxsys_netstack(lxsys_node_t *lnp)
{
	zone_t *zone = VTOLXSM(LXSTOV(lnp))->lxsysm_zone;

	return (netstack_hold_if_active(zone->zone_netstack));
}

ill_t *
lxsys_find_ill(ip_stack_t *ipst, uint_t ifindex)
{
	ill_t *ill;
	phyint_t *phyi;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    (void *) &ifindex, NULL);
	if (phyi != NULL) {
		/*
		 * Since interface information presented via /sys is not
		 * specific to IPv4 or IPv6, an ill reference from either
		 * protocol will be adequate.  Check both, starting with IPv4
		 * for a valid reference to use.
		 */
		for (ill = phyi->phyint_illv4; ill != phyi->phyint_illv6;
		    ill = phyi->phyint_illv6) {
			if (ill != NULL) {
				mutex_enter(&ill->ill_lock);
				if (!ILL_IS_CONDEMNED(ill)) {
					ill_refhold_locked(ill);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ill);
				}
				mutex_exit(&ill->ill_lock);
			}
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	return (NULL);
}


#define	LXSYSUIOBUFSZ	4096

lxsys_uiobuf_t *
lxsys_uiobuf_new(uio_t *uiop)
{
	/* Allocate memory for both lxsys_uiobuf and output buffer */
	int bufsize = LXSYSUIOBUFSZ;
	lxsys_uiobuf_t *uiobuf =
	    kmem_alloc(sizeof (lxsys_uiobuf_t) + bufsize, KM_SLEEP);

	uiobuf->uiop = uiop;
	uiobuf->buffer = (char *)&uiobuf[1];
	uiobuf->bufsize = bufsize;
	uiobuf->pos = uiobuf->buffer;
	uiobuf->beg = 0;
	uiobuf->error = 0;

	return (uiobuf);
}

void
lxsys_uiobuf_free(lxsys_uiobuf_t *uiobuf)
{
	ASSERT(uiobuf != NULL);
	ASSERT(uiobuf->pos == uiobuf->buffer);

	kmem_free(uiobuf, sizeof (lxsys_uiobuf_t) + uiobuf->bufsize);
}

void
lxsys_uiobuf_seterr(lxsys_uiobuf_t *uiobuf, int err)
{
	ASSERT(uiobuf->error == 0);

	uiobuf->error = err;
}

int
lxsys_uiobuf_flush(lxsys_uiobuf_t *uiobuf)
{
	off_t off = uiobuf->uiop->uio_offset;
	caddr_t uaddr = uiobuf->buffer;
	size_t beg = uiobuf->beg;
	size_t size = (uintptr_t)uiobuf->pos - (uintptr_t)uaddr;

	if (uiobuf->error == 0 && uiobuf->uiop->uio_resid != 0) {
		ASSERT(off >= beg);

		if (beg + size > off && off >= 0)
			uiobuf->error =
			    uiomove(uaddr + (off - beg), size - (off - beg),
			    UIO_READ, uiobuf->uiop);

		uiobuf->beg += size;
	}

	uiobuf->pos = uaddr;

	return (uiobuf->error);
}

void
lxsys_uiobuf_write(lxsys_uiobuf_t *uiobuf, const char *buf, size_t size)
{
	/* While we can still carry on */
	while (uiobuf->error == 0 && uiobuf->uiop->uio_resid != 0) {
		uintptr_t remain = (uintptr_t)uiobuf->bufsize -
		    ((uintptr_t)uiobuf->pos - (uintptr_t)uiobuf->buffer);

		/* Enough space in buffer? */
		if (remain >= size) {
			bcopy(buf, uiobuf->pos, size);
			uiobuf->pos += size;
			return;
		}

		/* Not enough space, so copy all we can and try again */
		bcopy(buf, uiobuf->pos, remain);
		uiobuf->pos += remain;
		(void) lxsys_uiobuf_flush(uiobuf);
		buf += remain;
		size -= remain;
	}
}

#define	TYPBUFFSIZE 256

void
lxsys_uiobuf_printf(lxsys_uiobuf_t *uiobuf, const char *fmt, ...)
{
	va_list args;
	char buff[TYPBUFFSIZE];
	int len;
	char *buffer;

	/* Can we still do any output */
	if (uiobuf->error != 0 || uiobuf->uiop->uio_resid == 0)
		return;

	va_start(args, fmt);

	/* Try using stack allocated buffer */
	len = vsnprintf(buff, TYPBUFFSIZE, fmt, args);
	if (len < TYPBUFFSIZE) {
		va_end(args);
		lxsys_uiobuf_write(uiobuf, buff, len);
		return;
	}

	/* Not enough space in pre-allocated buffer */
	buffer = kmem_alloc(len + 1, KM_SLEEP);

	/*
	 * We know we allocated the correct amount of space
	 * so no check on the return value
	 */
	(void) vsnprintf(buffer, len+1, fmt, args);
	lxsys_uiobuf_write(uiobuf, buffer, len);
	va_end(args);
	kmem_free(buffer, len+1);
}
