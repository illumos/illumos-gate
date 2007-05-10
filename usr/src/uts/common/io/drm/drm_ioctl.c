/*
 * drm_ioctl.h -- IOCTL processing for DRM -*- linux-c -*-
 * Created: Fri Jan  8 09:01:26 1999 by faith@valinux.com
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

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

/*
 * Beginning in revision 1.1 of the DRM interface, getunique will return
 * a unique in the form pci:oooo:bb:dd.f (o=domain, b=bus, d=device, f=function)
 * before setunique has been called.  The format for the bus-specific part of
 * the unique is not defined for any other bus.
 */
/*ARGSUSED*/
int
drm_getunique(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_unique_t	 u1;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_unique32_t u32;

		DRM_COPY_FROM_USER_IOCTL(u32,
			(drm_unique32_t *)data,
			sizeof (drm_unique32_t));
		u1.unique_len = u32.unique_len;
		u1.unique = (char __user *)(uintptr_t)u32.unique;
	} else
		DRM_COPY_FROM_USER_IOCTL(
			u1, (drm_unique_t *)data, sizeof (u1));

	if (u1.unique_len >= dev->unique_len) {
		if (dev->unique_len == 0) {
			DRM_ERROR("drm_getunique: dev->unique_len = 0");
			return (DRM_ERR(EFAULT));
		}
		if (DRM_COPY_TO_USER(u1.unique, dev->unique, dev->unique_len))
			return (DRM_ERR(EFAULT));
	}
	u1.unique_len = dev->unique_len;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_unique32_t u32;

		u32.unique_len = u1.unique_len;
		u32.unique = (caddr32_t)(uintptr_t)u1.unique;
		DRM_COPY_TO_USER_IOCTL((drm_unique32_t *)data, u32,
			sizeof (drm_unique32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_unique_t *)data, u1, sizeof (u1));

	return (0);
}

/*
 * Deprecated in DRM version 1.1, and will return EBUSY when setversion has
 * requested version 1.1 or greater.
 */
/*ARGSUSED*/
int
drm_setunique(DRM_IOCTL_ARGS)
{
	return (DRM_ERR(EINVAL));
}


static int
drm_set_busid(drm_device_t *dev)
{
	DRM_LOCK();

	if (dev->unique != NULL) {
		DRM_UNLOCK();
		return (DRM_ERR(EBUSY));
	}

	dev->unique_len = 20;
	dev->unique = drm_alloc(dev->unique_len + 1, DRM_MEM_DRIVER);
	if (dev->unique == NULL) {
		DRM_UNLOCK();
		return (DRM_ERR(ENOMEM));
	}

	(void) snprintf(dev->unique, dev->unique_len, "pci:%04x:%02x:%02x.%1x",
	    dev->pci_domain, dev->pci_bus, dev->pci_slot, dev->pci_func);

	DRM_UNLOCK();

	return (0);
}

/*ARGSUSED*/
int
drm_getmap(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_map_t	map;
	drm_local_map_t    *mapinlist;
	int		idx;
	int		i = 0;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map32_t map32;

		DRM_COPY_FROM_USER_IOCTL(map32,
			(drm_map32_t *)data,
			sizeof (drm_map32_t));
		map.offset = map32.offset;
		map.size = map32.size;
		map.type = map32.type;
		map.flags = map32.flags;
		map.handle = map32.handle;
		map.mtrr = map32.mtrr;
	} else
		DRM_COPY_FROM_USER_IOCTL(map, (drm_map_t *)data, sizeof (map));

	idx = map.offset;

	DRM_LOCK();
	if (idx < 0) {
		DRM_UNLOCK();
		return (DRM_ERR(EINVAL));
	}

	TAILQ_FOREACH(mapinlist, &dev->maplist, link) {
		if (i == idx) {
			map.offset = mapinlist->offset.off;
			map.size   = mapinlist->size;
			map.type   = mapinlist->type;
			map.flags  = mapinlist->flags;
			map.handle = (unsigned long long)(uintptr_t)
						mapinlist->handle;
			map.mtrr   = mapinlist->mtrr;
			break;
		}
		i++;
	}

	DRM_UNLOCK();

	if (mapinlist == NULL)
		return (DRM_ERR(EINVAL));

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map32_t map32;

		map32.offset = map.offset;
		map32.size = map.size;
		map32.type = map.type;
		map32.flags = map.flags;
		map32.handle = map.handle;
		map32.mtrr = map.mtrr;
		DRM_COPY_TO_USER_IOCTL((drm_map32_t *)data, map32,
			sizeof (drm_map32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_map_t *)data, map, sizeof (map));

	return (0);
}

/*ARGSUSED*/
int
drm_getclient(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_client_t	client;
	drm_file_t	*pt;
	int		idx;
	int		i = 0;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_client32_t client32;

		DRM_COPY_FROM_USER_IOCTL(client32,
			(drm_client32_t *)data,
			sizeof (drm_client32_t));
		client.idx = client32.idx;
		client.auth = client32.auth;
		client.pid = client32.pid;
		client.uid = client32.uid;
		client.magic = client32.magic;
		client.iocs = client32.iocs;
	} else
		DRM_COPY_FROM_USER_IOCTL(
			client, (drm_client_t *)data, sizeof (client));

	idx = client.idx;
	DRM_LOCK();
	TAILQ_FOREACH(pt, &dev->files, link) {
		if (i == idx) {
			client.auth  = pt->authenticated;
			client.pid   = pt->pid;
			client.uid   = pt->uid;
			client.magic = pt->magic;
			client.iocs  = pt->ioctl_count;
			DRM_UNLOCK();


			if (ddi_model_convert_from(mode & FMODELS) ==
				DDI_MODEL_ILP32) {

				drm_client32_t client32;

				client32.idx = client.idx;
				client32.auth = client.auth;
				client32.pid = client.pid;
				client32.uid = client.uid;
				client32.magic = client.magic;
				client32.iocs = client.iocs;

				DRM_COPY_TO_USER_IOCTL((drm_client32_t *)data,
					client32,
					sizeof (drm_client32_t));
			} else
				DRM_COPY_TO_USER_IOCTL((drm_client_t *)data,
					client, sizeof (client));

			return (0);
		}
		i++;
	}
	DRM_UNLOCK();
	return (DRM_ERR(EINVAL));
}

/*ARGSUSED*/
int
drm_getstats(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_stats_t	stats;
	int		i;

	bzero(&stats, sizeof (stats));

	DRM_LOCK();

	for (i = 0; i < dev->counters; i++) {
		if (dev->types[i] == _DRM_STAT_LOCK) {
			stats.data[i].value
				= (dev->lock.hw_lock
				    ? dev->lock.hw_lock->lock : 0);
		} else
			stats.data[i].value = atomic_read(&dev->counts[i]);
		stats.data[i].type  = dev->types[i];
	}

	stats.count = dev->counters;

	DRM_UNLOCK();

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_stats32_t stats32;
		stats32.count = stats.count;
		for (i = 0; i < 15; i++) {
			stats32.data[i].value = stats.data[i].value;
			stats32.data[i].type = stats.data[i].type;
		}
		DRM_COPY_TO_USER_IOCTL((drm_stats32_t *)data, stats32,
			sizeof (drm_stats32_t));
	} else
		DRM_COPY_TO_USER_IOCTL(
			(drm_stats_t *)data, stats, sizeof (stats));

	return (0);
}

#define	DRM_IF_MAJOR	1
#define	DRM_IF_MINOR	4

/*ARGSUSED*/
int
drm_setversion(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_set_version_t sv;
	drm_set_version_t retv;
	int if_version;

	DRM_COPY_FROM_USER_IOCTL(sv, (drm_set_version_t *)data, sizeof (sv));

	retv.drm_di_major = DRM_IF_MAJOR;
	retv.drm_di_minor = DRM_IF_MINOR;
	retv.drm_dd_major = dev->driver_major;
	retv.drm_dd_minor = dev->driver_minor;

	DRM_COPY_TO_USER_IOCTL((drm_set_version_t *)data, retv, sizeof (sv));

	if (sv.drm_di_major != -1) {
		if (sv.drm_di_major != DRM_IF_MAJOR ||
		    sv.drm_di_minor < 0 || sv.drm_di_minor > DRM_IF_MINOR)
			return (DRM_ERR(EINVAL));
		if_version = DRM_IF_VERSION(sv.drm_di_major, sv.drm_dd_minor);
		dev->if_version = DRM_MAX(if_version, dev->if_version);
		if (sv.drm_di_minor >= 1) {
			/*
			 * Version 1.1 includes tying of DRM to specific device
			 */
			(void) drm_set_busid(dev);
		}
	}

	if (sv.drm_dd_major != -1) {
		if (sv.drm_dd_major != dev->driver_major ||
		    sv.drm_dd_minor < 0 || sv.drm_dd_minor > dev->driver_minor)
			return (DRM_ERR(EINVAL));
	}
	return (0);
}


/*ARGSUSED*/
int
drm_noop(DRM_IOCTL_ARGS)
{
	DRM_DEBUG("drm_noop\n");
	return (0);
}

/*ARGSUSED*/
int
drm_version(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_version_t version;
	int len;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_version32_t version32;

		DRM_COPY_FROM_USER_IOCTL(version32,
			(drm_version32_t *)data,
			sizeof (drm_version32_t));
		version.version_major = version32.version_major;
		version.version_minor = version32.version_minor;
		version.version_patchlevel = version32.version_patchlevel;
		version.name_len = version32.name_len;
		version.name = (char __user *)(uintptr_t)version32.name;
		version.date_len = version32.date_len;
		version.date = (char __user *)(uintptr_t)version32.date;
		version.desc_len = version32.desc_len;
		version.desc = (char __user *)(uintptr_t)version32.desc;
	} else
		DRM_COPY_FROM_USER_IOCTL(
			version, (drm_version_t *)data, sizeof (version));

#define	DRM_COPY(name, value)                                         \
	len = strlen(value);                                          \
	if (len > name##_len) len = name##_len;                       \
	name##_len = strlen(value);                                   \
	if (len && name) {                                            \
		if (DRM_COPY_TO_USER(name, value, len))             \
			return (DRM_ERR(EFAULT));                         \
	}

	version.version_major = dev->driver_major;
	version.version_minor = dev->driver_minor;
	version.version_patchlevel = dev->driver_patchlevel;

	DRM_COPY(version.name, dev->driver_name);
	DRM_COPY(version.date, dev->driver_date);
	DRM_COPY(version.desc, dev->driver_desc);

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_version32_t version32;

		version32.version_major = version.version_major;
		version32.version_minor = version.version_minor;
		version32.version_patchlevel = version.version_patchlevel;
		version32.name_len = version.name_len;
		version32.name = (caddr32_t)(uintptr_t)version.name;
		version32.date_len = version.date_len;
		version32.date = (caddr32_t)(uintptr_t)version.date;
		version32.desc_len = version.desc_len;
		version32.desc = (caddr32_t)(uintptr_t)version.desc;
		DRM_COPY_TO_USER_IOCTL((drm_version32_t *)data, version32,
			sizeof (drm_version32_t));
	} else
		DRM_COPY_TO_USER_IOCTL(
			(drm_version_t *)data, version, sizeof (version));

	return (0);
}
