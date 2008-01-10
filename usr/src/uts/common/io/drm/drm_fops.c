/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* BEGIN CSTYLED */

/* drm_fops.h -- File operations for DRM -*- linux-c -*-
 * Created: Mon Jan  4 08:58:31 1999 by faith@valinux.com
 */
/*-
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
 *    Daryll Strauss <daryll@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/* END CSTYLED */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

/*ARGSUSED*/
drm_file_t *
drm_find_file_by_proc(drm_device_t *dev, cred_t *credp)
{
	pid_t pid = ddi_get_pid();
	drm_file_t *priv;

	TAILQ_FOREACH(priv, &dev->files, link)
	if (priv->pid == pid)
		return (priv);
	return (NULL);
}

/* drm_open_helper is called whenever a process opens /dev/drm. */
/*ARGSUSED*/
int
drm_open_helper(drm_device_t *dev, int flags, int otyp, cred_t *credp)
{
	drm_file_t   *priv;
	pid_t pid;
	int retcode;

	if (flags & FEXCL)
		return (EBUSY); /* No exclusive opens */
	dev->flags = flags;

	pid = ddi_get_pid();
	DRM_DEBUG("drm_open_helper :pid = %d", pid);

	DRM_LOCK();
	priv = drm_find_file_by_proc(dev, credp);
	if (priv) {
		priv->refs++;
	} else {
		priv = drm_alloc(sizeof (*priv), DRM_MEM_FILES);
		if (priv == NULL) {
			DRM_UNLOCK();
			return (ENOMEM);
		}
		bzero(priv, sizeof (*priv));

		priv->uid		= crgetsuid(credp);
		priv->pid		= pid;

		priv->refs		= 1;
		priv->minor		= 5;	/* just for hack */
		priv->ioctl_count 	= 0;

		/* for compatibility root is always authenticated */
		priv->authenticated	= DRM_SUSER(credp);

		if (dev->driver->open) {
			retcode = dev->driver->open(dev, priv);
			if (retcode != 0) {
				drm_free(priv, sizeof (*priv), DRM_MEM_FILES);
				DRM_UNLOCK();
				return (retcode);
			}
		}

		/* first opener automatically becomes master */
		priv->master = TAILQ_EMPTY(&dev->files);

		TAILQ_INSERT_TAIL(&dev->files, priv, link);
	}
	DRM_UNLOCK();
	return (0);
}
