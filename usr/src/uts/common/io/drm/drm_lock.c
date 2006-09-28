/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lock.c -- IOCTLs for locking -*- linux-c -*-
 * Created: Tue Feb  2 08:37:54 1999 by faith@valinux.com
 */
/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

int
drm_lock_held(void *info)
{
	__volatile__ unsigned int *lock;

	lock = (__volatile__ unsigned int *)info;
	return (_DRM_LOCK_IS_HELD(*lock));
}

int
drm_lock_take(__volatile__ unsigned int *lock, unsigned int context)
{
	unsigned int old, new;

	do {
		old = *lock;
		if (old & _DRM_LOCK_HELD) new = old | _DRM_LOCK_CONT;
		else			  new = context | _DRM_LOCK_HELD;
	} while (!atomic_cmpset_int(lock, old, new));

	if (_DRM_LOCKING_CONTEXT(old) == context) {
		if (old & _DRM_LOCK_HELD) {
			if (context != DRM_KERNEL_CONTEXT) {
				DRM_ERROR("%d holds heavyweight lock\n",
				    context);
			}
			return (0);
		}
	}
	if (new == (context | _DRM_LOCK_HELD)) {
				/* Have lock */
		return (1);
	}
	return (0);
}

/*
 * This takes a lock forcibly and hands it to context.	Should ONLY be used
 * inside *_unlock to give lock to kernel before calling *_dma_schedule.
 */
int
drm_lock_transfer(drm_device_t *dev, __volatile__ unsigned int *lock,
    unsigned int context)
{
	unsigned int old, new;

	dev->lock.filp = NULL;
	do {
		old  = *lock;
		new  = context | _DRM_LOCK_HELD;
	} while (!atomic_cmpset_int(lock, old, new));

	return (1);
}

int
drm_lock_free(drm_device_t *dev, __volatile__ unsigned int *lock,
    unsigned int context)
{
	unsigned int old, new;

	mutex_enter(&(dev->lock.lock_mutex));
	dev->lock.filp = NULL;
	do {
		old  = *lock;
		new  = 0;
	} while (!atomic_cmpset_int(lock, old, new));

	if (_DRM_LOCK_IS_HELD(old) && _DRM_LOCKING_CONTEXT(old) != context) {
		DRM_ERROR("%d freed heavyweight lock held by %d\n",
		    context, _DRM_LOCKING_CONTEXT(old));
		return (1);
	}
	cv_broadcast(&(dev->lock.lock_cv));
	mutex_exit(&(dev->lock.lock_mutex));
	return (0);
}

/*ARGSUSED*/
int
drm_lock(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_lock_t lock;
	int ret = 0;

	DRM_COPY_FROM_USER_IOCTL(lock, (drm_lock_t *)data, sizeof (lock));

	if (lock.context == DRM_KERNEL_CONTEXT) {
		return (DRM_ERR(EINVAL));
	}

	DRM_DEBUG("%d (pid %d) requests lock (0x%08x), flags = 0x%08x\n",
	    lock.context, DRM_CURRENTPID, dev->lock.hw_lock->lock, lock.flags);

	if (dev->use_dma_queue && lock.context < 0)
		return (DRM_ERR(EINVAL));

	mutex_enter(&(dev->lock.lock_mutex));
	DRM_DEBUG("mutex enter\n");
	for (;;) {
		if (drm_lock_take(&dev->lock.hw_lock->lock, lock.context)) {
			DRM_DEBUG("drm_lock_take enter\n");
			dev->lock.filp = (void *)(uintptr_t)DRM_CURRENTPID;
			dev->lock.lock_time = jiffies;
			atomic_inc_32(&dev->counts[_DRM_STAT_LOCKS]);
			break;  /* Got lock */
		}
		DRM_DEBUG("Drm_lock: cv_wait\n");
		ret = cv_wait_sig(&(dev->lock.lock_cv),
		    &(dev->lock.lock_mutex));

		if (ret == 0) {
			mutex_exit(&(dev->lock.lock_mutex));
			return (-1);
		}
	}
	DRM_DEBUG("before mutex_exit\n");
	mutex_exit(&(dev->lock.lock_mutex));
	DRM_DEBUG("drm_lock: %d %s\n", lock.context,
	    ret ? "interrupted" : "has lock");

	if (dev->dma_quiescent != NULL &&
	    (lock.flags & _DRM_LOCK_QUIESCENT))
		dev->dma_quiescent(dev);

	return (0);
}

/*ARGSUSED*/
int
drm_unlock(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_lock_t lock;

	DRM_COPY_FROM_USER_IOCTL(lock, (drm_lock_t *)data, sizeof (lock));

	if (lock.context == DRM_KERNEL_CONTEXT) {
		DRM_ERROR("Process %d using kernel context %d\n",
		    DRM_CURRENTPID, lock.context);
		return (DRM_ERR(EINVAL));
	}

	atomic_inc_32(&dev->counts[_DRM_STAT_UNLOCKS]);

	DRM_LOCK();
	(void) drm_lock_transfer(dev, &dev->lock.hw_lock->lock,
	    DRM_KERNEL_CONTEXT);

	if (drm_lock_free(dev, &dev->lock.hw_lock->lock, DRM_KERNEL_CONTEXT)) {
		DRM_ERROR("drm_unlock\n");
	}
	DRM_UNLOCK();

	return (0);
}
