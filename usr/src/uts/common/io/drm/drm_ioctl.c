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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm_io32.h"

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

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_unique_32_t u32;

		DRM_COPYFROM_WITH_RETURN(&u32, (void *)data, sizeof (u32));
		u1.unique_len = u32.unique_len;
		u1.unique = (char __user *)(uintptr_t)u32.unique;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&u1, (void *)data, sizeof (u1));

	if (u1.unique_len >= dev->unique_len) {
		if (dev->unique_len == 0) {
			DRM_ERROR("drm_getunique: dev->unique_len = 0");
			return (EFAULT);
		}
		if (DRM_COPY_TO_USER(u1.unique, dev->unique, dev->unique_len))
			return (EFAULT);
	}
	u1.unique_len = dev->unique_len;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_unique_32_t u32;

		u32.unique_len = (uint32_t)u1.unique_len;
		u32.unique = (caddr32_t)(uintptr_t)u1.unique;
		DRM_COPYTO_WITH_RETURN((void *)data, &u32, sizeof (u32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &u1, sizeof (u1));

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
	return (EINVAL);
}


static int
drm_set_busid(drm_device_t *dev)
{
	DRM_LOCK();

	if (dev->unique != NULL) {
		DRM_UNLOCK();
		return (EBUSY);
	}

	dev->unique_len = 20;
	dev->unique = drm_alloc(dev->unique_len + 1, DRM_MEM_DRIVER);
	if (dev->unique == NULL) {
		DRM_UNLOCK();
		return (ENOMEM);
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

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map_32_t map32;

		DRM_COPYFROM_WITH_RETURN(&map32, (void *)data, sizeof (map32));
		map.offset = map32.offset;
		map.size = map32.size;
		map.type = map32.type;
		map.flags = map32.flags;
		map.handle = map32.handle;
		map.mtrr = map32.mtrr;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&map, (void *)data, sizeof (map));

	idx = (int)map.offset;

	DRM_LOCK();
	if (idx < 0) {
		DRM_UNLOCK();
		return (EINVAL);
	}

	TAILQ_FOREACH(mapinlist, &dev->maplist, link) {
		if (i == idx) {
			map.offset = mapinlist->offset;
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
		return (EINVAL);

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map_32_t map32;

		map32.offset = map.offset;
		map32.size = (uint32_t)map.size;
		map32.type = map.type;
		map32.flags = map.flags;
		map32.handle = (uintptr_t)map.handle;
		map32.mtrr = map.mtrr;
		DRM_COPYTO_WITH_RETURN((void *)data, &map32, sizeof (map32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &map, sizeof (map));

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

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_client_32_t client32;

		DRM_COPYFROM_WITH_RETURN(&client32, (void *)data,
		    sizeof (client32));
		client.idx = client32.idx;
		client.auth = client32.auth;
		client.pid = client32.pid;
		client.uid = client32.uid;
		client.magic = client32.magic;
		client.iocs = client32.iocs;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&client, (void *)data,
		    sizeof (client));

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

#ifdef	_MULTI_DATAMODEL
			if (ddi_model_convert_from(mode & FMODELS) ==
			    DDI_MODEL_ILP32) {
				drm_client_32_t client32;

				client32.idx = client.idx;
				client32.auth = client.auth;
				client32.pid = (uint32_t)client.pid;
				client32.uid = (uint32_t)client.uid;
				client32.magic = (uint32_t)client.magic;
				client32.iocs = (uint32_t)client.iocs;

				DRM_COPYTO_WITH_RETURN((void *)data, &client32,
				    sizeof (client32));
			} else
#endif
				DRM_COPYTO_WITH_RETURN((void *)data,
				    &client, sizeof (client));

			return (0);
		}
		i++;
	}
	DRM_UNLOCK();
	return (EINVAL);
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

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_stats_32_t stats32;
		stats32.count = (uint32_t)stats.count;
		for (i = 0; i < 15; i++) {
			stats32.data[i].value = stats.data[i].value;
			stats32.data[i].type = stats.data[i].type;
		}
		DRM_COPYTO_WITH_RETURN((void *)data, &stats32,
		    sizeof (stats32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &stats, sizeof (stats));

	return (0);
}

#define	DRM_IF_MAJOR	1
#define	DRM_IF_MINOR	2

/*ARGSUSED*/
int
drm_setversion(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_set_version_t sv;
	drm_set_version_t retv;
	int if_version;

	DRM_COPYFROM_WITH_RETURN(&sv, (void *)data, sizeof (sv));

	retv.drm_di_major = DRM_IF_MAJOR;
	retv.drm_di_minor = DRM_IF_MINOR;
	retv.drm_dd_major = dev->driver->driver_major;
	retv.drm_dd_minor = dev->driver->driver_minor;

	DRM_COPYTO_WITH_RETURN((void *)data, &retv, sizeof (sv));

	if (sv.drm_di_major != -1) {
		if (sv.drm_di_major != DRM_IF_MAJOR ||
		    sv.drm_di_minor < 0 || sv.drm_di_minor > DRM_IF_MINOR)
			return (EINVAL);
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
		if (sv.drm_dd_major != dev->driver->driver_major ||
		    sv.drm_dd_minor < 0 ||
		    sv.drm_dd_minor > dev->driver->driver_minor)
			return (EINVAL);
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
	size_t len;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_version_32_t version32;

		DRM_COPYFROM_WITH_RETURN(&version32,
		    (void *)data, sizeof (drm_version_32_t));
		version.name_len = version32.name_len;
		version.name = (char *)(uintptr_t)version32.name;
		version.date_len = version32.date_len;
		version.date = (char *)(uintptr_t)version32.date;
		version.desc_len = version32.desc_len;
		version.desc = (char *)(uintptr_t)version32.desc;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&version, (void *)data,
		    sizeof (version));

#define	DRM_COPY(name, value)                                         \
	len = strlen(value);                                          \
	if (len > name##_len) len = name##_len;                       \
		name##_len = strlen(value);                                   \
	if (len && name) {                                            \
		if (DRM_COPY_TO_USER(name, value, len))             \
			return (EFAULT);                         \
	}

	version.version_major = dev->driver->driver_major;
	version.version_minor = dev->driver->driver_minor;
	version.version_patchlevel = dev->driver->driver_patchlevel;

	DRM_COPY(version.name, dev->driver->driver_name);
	DRM_COPY(version.date, dev->driver->driver_date);
	DRM_COPY(version.desc, dev->driver->driver_desc);

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_version_32_t version32;

		version32.version_major = version.version_major;
		version32.version_minor = version.version_minor;
		version32.version_patchlevel = version.version_patchlevel;
		version32.name_len = (uint32_t)version.name_len;
		version32.name = (caddr32_t)(uintptr_t)version.name;
		version32.date_len = (uint32_t)version.date_len;
		version32.date = (caddr32_t)(uintptr_t)version.date;
		version32.desc_len = (uint32_t)version.desc_len;
		version32.desc = (caddr32_t)(uintptr_t)version.desc;
		DRM_COPYTO_WITH_RETURN((void *)data, &version32,
		    sizeof (drm_version_32_t));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &version,
		    sizeof (version));

	return (0);
}
