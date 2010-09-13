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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/mman.h>
#include <sys/systm.h>
#include <vm/xhat.h>
#include <vm/page.h>
#include <vm/as.h>

int xhat_debug = 0;

krwlock_t xhat_provider_rwlock;
xhat_provider_t *xhat_provider = NULL;

void
xhat_init()
{
	rw_init(&xhat_provider_rwlock, NULL, RW_DEFAULT, NULL);
}



int
xhat_provider_register(xhat_provider_t *provider)
{
	/* strlen("_cache") = 7 */
	char	cache_name[XHAT_CACHE_NAMELEN + 7];


	if (provider->xhat_provider_version != XHAT_PROVIDER_VERSION) {
		cmn_err(CE_WARN, "XHAT provider version mismatch");
		return (-1);
	}

	if ((XHAT_POPS(provider)->xhat_alloc == NULL) ||
	    (XHAT_POPS(provider)->xhat_free == NULL)) {
		cmn_err(CE_WARN, "Malformed XHAT provider");
		return (-1);
	}

	/* Allocate kmem_cache which will manage xhat blocks */
	provider->xblkcache->free_blks = NULL;
	(void) strncpy(cache_name, provider->xhat_provider_name,
	    XHAT_CACHE_NAMELEN);
	(void) strcat(cache_name, "_cache");
	provider->xblkcache->cache = kmem_cache_create(cache_name,
	    provider->xhat_provider_blk_size, 0, NULL, NULL,
	    provider->xblkcache->reclaim,
	    (void *)provider, NULL, 0);
	if (provider->xblkcache->cache == NULL) {
		cmn_err(CE_WARN, "Failed to allocate cache for %s",
		    provider->xhat_provider_name);
		return (-1);
	}

	mutex_init(&provider->xblkcache->lock, NULL, MUTEX_DEFAULT, NULL);


	/* Insert provider in the global list */
	rw_enter(&xhat_provider_rwlock, RW_WRITER);
	provider->next = xhat_provider;
	provider->prev = NULL;
	if (xhat_provider)
		xhat_provider->prev = provider;
	xhat_provider = provider;
	xhat_provider->xhat_provider_refcnt = 0;
	rw_exit(&xhat_provider_rwlock);
	return (0);
}



int
xhat_provider_unregister(xhat_provider_t *provider)
{
	if (provider->xhat_provider_version != XHAT_PROVIDER_VERSION)
		return (-1);

	rw_enter(&xhat_provider_rwlock, RW_WRITER);

	if (provider->xhat_provider_refcnt) {
		rw_exit(&xhat_provider_rwlock);
		return (-1);
	}

	if (provider->next)
		provider->next->prev = provider->prev;
	if (provider->prev)
		provider->prev->next = provider->next;
	else
		xhat_provider = provider->next;
	provider->prev = NULL;
	provider->next = NULL;
	rw_exit(&xhat_provider_rwlock);

	/* Free all xblks that are sitting on free_blks list */
	provider->xblkcache->reclaim(provider);

	kmem_cache_destroy(provider->xblkcache->cache);

	return (0);
}



/* Attaches an XHAT to the address space */
int
xhat_attach_xhat(xhat_provider_t *provider, struct as *as,
    struct xhat **xhatp, void *arg)
{
	struct xhat *xh;



	xh = XHAT_POPS(provider)->xhat_alloc(arg);
	if (xh == NULL) {
		*xhatp = NULL;
		return (XH_PRVDR);
	}

	mutex_init(&xh->xhat_lock, NULL, MUTEX_DEFAULT, NULL);
	xh->xhat_provider = provider;

	rw_enter(&xhat_provider_rwlock, RW_WRITER);
	provider->xhat_provider_refcnt++;
	rw_exit(&xhat_provider_rwlock);

	mutex_enter(&as->a_contents);

	/* Is address space busy (being freed, dup'd or swapped)? */
	if (AS_ISBUSY(as)) {
		mutex_exit(&as->a_contents);
		XHAT_POPS(provider)->xhat_free(xh);

		rw_enter(&xhat_provider_rwlock, RW_WRITER);
		provider->xhat_provider_refcnt--;
		rw_exit(&xhat_provider_rwlock);

		*xhatp = NULL;
		return (XH_ASBUSY);
	}

	xh->xhat_as = as;
	xh->xhat_refcnt = 0;
	xh->holder = NULL;
	xh->arg = arg;
	xh->next = (struct xhat *)as->a_xhat;
	if (xh->next)
		xh->next->prev = xh;
	as->a_xhat = xh;
	mutex_exit(&as->a_contents);
	*xhatp = xh;
	return (0);
}


int
xhat_detach_xhat(xhat_provider_t *provider, struct as *as)
{
	struct xhat *xh;


	mutex_enter(&as->a_contents);

	for (xh = (struct xhat *)as->a_xhat; xh != NULL; xh = xh->next)
		if (xh->xhat_provider == provider) {


			if (xh->holder != NULL) {
				/*
				 * The address space is being freed,
				 * dup'd or swapped out.
				 * If we are the thread which doing one
				 * of those operations, we can go ahead
				 * and free up the XHAT.
				 * Otherwise, return.
				 */
				if (xh->holder != curthread) {
					mutex_exit(&as->a_contents);
					return (XH_ASBUSY);
				} else
					xhat_hat_rele(xh);
			}

			if (xh->xhat_refcnt > 0) {
				/*
				 * There are still "users" of the XHAT.
				 * This may be either because the caller
				 * forgot to free something up (which is a bug)
				 * or because xhat_op_all() is in progress.
				 * Since we are not allowing any of
				 * xhat_op_all's ops to call xhat_detach_xhat(),
				 * This can only be some other thread. It
				 * may want to wait a bit and retry.
				 */


				/* Restore the hold on the XHAT */
				if (xh->holder == curthread)
					xhat_hat_hold(xh);

				mutex_exit(&as->a_contents);
				return (XH_XHHELD);
			}

			rw_enter(&xhat_provider_rwlock, RW_WRITER);
			provider->xhat_provider_refcnt--;
			rw_exit(&xhat_provider_rwlock);

			if (xh->next)
				xh->next->prev = xh->prev;
			if (xh->prev)
				xh->prev->next = xh->next;
			else
				as->a_xhat = (void *) xh->next;
			mutex_exit(&as->a_contents);

			XHAT_POPS(provider)->xhat_free(xh);

			return (0);
		}
	mutex_exit(&as->a_contents);
	return (XH_NOTATTCHD);
}

void
xhat_hat_hold(struct xhat *xhat)
{
	mutex_enter(&xhat->xhat_lock);
	xhat->xhat_refcnt++;
	mutex_exit(&xhat->xhat_lock);
}

void
xhat_hat_rele(struct xhat *xhat)
{
	mutex_enter(&xhat->xhat_lock);
	xhat->xhat_refcnt--;
	ASSERT(xhat->xhat_refcnt >= 0);
	mutex_exit(&xhat->xhat_lock);
}


int
xhat_hat_holders(struct xhat *xhat)
{
	return (xhat->xhat_refcnt);
}


/*
 * Assumes that address space is already locked
 * and that AS_FREE is set for as->a_flags.
 */
void
xhat_free_start_all(struct as *as)
{
	struct xhat *xh, *xh_nxt;


	ASSERT(AS_ISBUSY(as));

	mutex_enter(&as->a_contents);
	xh = (struct xhat *)as->a_xhat;

	/*
	 * Simply calling xhat_hat_hold() won't work because we will
	 * not be able to succeed in xhat_detach_xhat(), which may
	 * get called from here. We need to know _who_ the holder is.
	 */
	if (xh != NULL) {
		xhat_hat_hold(xh);
		ASSERT(xh->holder == NULL);
		xh->holder = curthread;
	}

	while (xh != NULL) {

		xh_nxt = xh->next;
		if (xh_nxt != NULL) {
			ASSERT(xh_nxt->holder == NULL);
			xhat_hat_hold(xh_nxt);
			xh_nxt->holder = curthread;
		}

		mutex_exit(&as->a_contents);

		XHAT_FREE_START(xh);

		mutex_enter(&as->a_contents);

		xh = xh_nxt;
	}

	mutex_exit(&as->a_contents);
}



/*
 * Assumes that address space is already locked.
 * Since xhat_free_start_all() must have been called
 * earlier, for all XHATs holder is set to curthread.
 * Also, since AS_BUSY is set for as->a_flags, no new
 * XHATs could have been added.
 */
void
xhat_free_end_all(struct as *as)
{

	struct xhat *xh, *xh_nxt;

	ASSERT(AS_ISBUSY(as));

	mutex_enter(&as->a_contents);
	xh = (struct xhat *)as->a_xhat;


	while (xh != NULL) {

		ASSERT(xh->holder == curthread);

		xh_nxt = xh->next;

		mutex_exit(&as->a_contents);

		XHAT_FREE_END(xh);

		mutex_enter(&as->a_contents);

		xh = xh_nxt;
	}

	mutex_exit(&as->a_contents);
}


/* Assumes that address space is already locked */

/* ARGSUSED */
int
xhat_dup_all(struct as *as, struct as *newas, caddr_t addr, size_t len,
    uint_t flag)
{
	/* This is not supported. Should we return some sort of error? */

	ASSERT(AS_ISBUSY(as));

	return (0);
}


/* Assumes that address space is already locked */
void
xhat_swapout_all(struct as *as)
{
	struct xhat *xh, *xh_nxt;


	ASSERT(AS_ISBUSY(as));

	mutex_enter(&as->a_contents);
	xh = (struct xhat *)as->a_xhat;

	if (xh != NULL) {
		xhat_hat_hold(xh);
		ASSERT(xh->holder == NULL);
		xh->holder = curthread;
	}


	while (xh != NULL) {

		xh_nxt = xh->next;
		if (xh_nxt != NULL) {
			ASSERT(xh_nxt->holder == NULL);
			xhat_hat_hold(xh_nxt);
			xh_nxt->holder = curthread;
		}

		mutex_exit(&as->a_contents);

		XHAT_SWAPOUT(xh);

		mutex_enter(&as->a_contents);

		/*
		 * If the xh is still there (i.e. swapout did not
		 * destroy it), clear the holder field.
		 * xh_nxt->prev couldn't have been changed in xhat_attach_xhat()
		 * because AS_BUSY is set. xhat_detach_xhat() also couldn't
		 * have modified it because (holder != NULL).
		 * If there is only one XHAT, just see if a_xhat still
		 * points to us.
		 */
		if (((xh_nxt != NULL) && (xh_nxt->prev == xh)) ||
		    ((as->a_xhat != NULL) && (as->a_xhat == xh))) {
			xhat_hat_rele(xh);
			xh->holder = NULL;
		}

		xh = xh_nxt;
	}

	mutex_exit(&as->a_contents);
}




/*
 * In the following routines, the appropriate xhat_op
 * should never attempt to call xhat_detach_xhat(): it will
 * never succeed since the XHAT is held.
 */


#define	XHAT_UNLOAD_CALLBACK_OP	(0)
#define	XHAT_SETATTR_OP		(1)
#define	XHAT_CLRATTR_OP		(2)
#define	XHAT_CHGATTR_OP		(3)
#define	XHAT_CHGPROT_OP		(4)
#define	XHAT_UNSHARE_OP		(5)


static void
xhat_op_all(int op, struct as *as, caddr_t addr,
    size_t len, uint_t flags, void *ptr)
{
	struct xhat *xh, *xh_nxt;

	mutex_enter(&as->a_contents);
	xh = (struct xhat *)as->a_xhat;

	while (xh != NULL) {

		xhat_hat_hold(xh);

		xh_nxt = xh->next;
		if (xh_nxt != NULL)
			xhat_hat_hold(xh_nxt);

		mutex_exit(&as->a_contents);

		switch (op) {
		case XHAT_UNLOAD_CALLBACK_OP:
			XHAT_UNLOAD_CALLBACK(xh, addr,
			    len, flags, (hat_callback_t *)ptr);
			break;
		case XHAT_SETATTR_OP:
			XHAT_SETATTR(xh, addr, len, flags);
			break;
		case XHAT_CLRATTR_OP:
			XHAT_CLRATTR(xh, addr, len, flags);
			break;
		case XHAT_CHGATTR_OP:
			XHAT_CHGATTR(xh, addr, len, flags);
			break;
		case XHAT_CHGPROT_OP:
			XHAT_CHGPROT(xh, addr, len, flags);
			break;
		case XHAT_UNSHARE_OP:
			XHAT_UNSHARE(xh, addr, len);
			break;
		default:
			panic("Unknown op %d in xhat_op_all", op);
		}

		mutex_enter(&as->a_contents);

		/*
		 * Both pointers are still valid because both
		 * XHATs are held.
		 */
		xhat_hat_rele(xh);
		if (xh_nxt != NULL)
			xhat_hat_rele(xh_nxt);
		xh = xh_nxt;
	}

	mutex_exit(&as->a_contents);
}



void
xhat_unload_callback_all(struct as *as, caddr_t addr, size_t len, uint_t flags,
    hat_callback_t *callback)
{
	xhat_op_all(XHAT_UNLOAD_CALLBACK_OP, as, addr, len, flags, callback);
}


void
xhat_setattr_all(struct as *as, caddr_t addr, size_t len, uint_t attr)
{
	xhat_op_all(XHAT_SETATTR_OP, as, addr, len, attr, NULL);
}



void
xhat_clrattr_all(struct as *as, caddr_t addr, size_t len, uint_t attr)
{
	xhat_op_all(XHAT_CLRATTR_OP, as, addr, len, attr, NULL);
}


void
xhat_chgattr_all(struct as *as, caddr_t addr, size_t len, uint_t attr)
{
	xhat_op_all(XHAT_CHGATTR_OP, as, addr, len, attr, NULL);
}


void
xhat_chgprot_all(struct as *as, caddr_t addr, size_t len, uint_t prot)
{
	xhat_op_all(XHAT_CHGPROT_OP, as, addr, len, prot, NULL);
}


void
xhat_unshare_all(struct as *as, caddr_t addr, size_t len)
{
	xhat_op_all(XHAT_UNSHARE_OP, as, addr, len, 0, NULL);
}
