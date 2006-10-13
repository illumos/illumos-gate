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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/stat.h>
#include <libsysevent.h>
#include <sys/sysevent/dev.h>

#include "vold.h"

extern void	reread_config(int);

static void	event_handler(sysevent_t *);
static void	device_add(sysevent_t *);

static sysevent_handle_t	*shp;

/*
 * establish channel between syseventd.
 */
int
sysevent_init(void)
{
	const char	*subcl[2];

	shp = sysevent_bind_handle(event_handler);
	if (shp == NULL)
		return (1);

	subcl[0] = ESC_DISK;
	if (sysevent_subscribe_event(shp, EC_DEV_ADD, subcl, 1) != 0) {
		sysevent_unbind_handle(shp);
		return (1);
	}
	debug(5, "sysevent_init completed successfully\n");

	return (0);
}

void
sysevent_fini(void)
{
	sysevent_unbind_handle(shp);
	shp = NULL;
	debug(5, "sysevent_fini completed successfully\n");
}

/*
 * sysevent handler
 */
static void
event_handler(sysevent_t *ev)
{
	char		*class;
	char		*subclass;

	debug(5, "sysevent handler started\n");

	/* Quick return for uninteresting events */
	if ((class = sysevent_get_class_name(ev)) == NULL)
		return;

	if ((subclass = sysevent_get_subclass_name(ev)) == NULL)
		return;

	debug(3, "class = %s, sub = %s\n", class, subclass);

	if (strcmp(class, EC_DEV_ADD) == 0) {
		if (strcmp(subclass, ESC_DISK) != 0)
			return;
		device_add(ev);
	}
}

/*
 * check the event and let vold manage/unmange the device.
 */
static void
device_add(sysevent_t *ev)
{
	nvlist_t *attr_list;
	struct stat st;
	char	*name, *cname;
	int	len, fd, removable;

	debug(5, "device_add started\n");

	attr_list = NULL;
	cname = NULL;

	if (sysevent_get_attr_list(ev, &attr_list) != 0)
		return;

	if (nvlist_lookup_string(attr_list, DEV_NAME, &name) != 0)
		goto out;

	debug(1, "sysevent: device_add %s\n", name);

#if notdef
	/*
	 * see if we allow hotplug
	 */
	if (!accept_hotplugin) {
		debug(1, "hotplug event rejected\n");
		goto out;
	}
#endif

	/*
	 * check to see if the device exists.
	 */
	if (stat(name, &st) < 0) {
		/*
		 * can be a SCSI disk. add slice/partition tag to the
		 * device name and notify vold.
		 */
		len = strlen(name);
		cname = vold_malloc(len + 3);
		(void) strcpy(cname, name);
		(void) strcpy(cname + len, "s2");
		if (stat(cname, &st) < 0) {
			/*
			 * seems no s2 partition. try p0.
			 */
			(void) strcpy(cname + len, "p0");
			if (stat(cname, &st) < 0)
				goto out;
		}
		name = cname;
	}

	if (!S_ISCHR(st.st_mode))
		goto out;

	if ((fd = open(name, O_RDONLY|O_NONBLOCK)) < 0) {
		debug(2, "cannot open the device, %d\n", errno);
		goto out;
	}

	if (ioctl(fd, DKIOCREMOVABLE, &removable) < 0) {
		debug(2, "DKIOCREMOVABLE failed, %d\n", errno);
		(void) close(fd);
		goto out;
	}

	if (!removable) {
		debug(2, "%s is not a removable media\n", name);
		(void) close(fd);
		goto out;
	}
	(void) close(fd);

	/*
	 * let main thread rescan devices
	 */
	debug(2, "%s is a removable media\n", name);

	reread_config(0);

out:
	if (cname != NULL)
		free(cname);
	nvlist_free(attr_list);
}
