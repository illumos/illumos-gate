/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Talks to Xen Store to figure out what devices we have.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 * Copyright (C) 2005 Mike Wray, Hewlett-Packard
 * Copyright (C) 2005 XenSource Ltd
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#endif
#include <sys/hypervisor.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/public/io/xs_wire.h>

static int
read_otherend_details(struct xenbus_device *xendev,
			char *id_node, char *path_node)
{
	int err = xenbus_gather(XBT_NULL, xendev->nodename,
	    id_node, "%i", &xendev->otherend_id, path_node, NULL,
	    &xendev->otherend, NULL);
	if (err) {
		xenbus_dev_fatal(xendev, err,
		    "reading other end details from %s", xendev->nodename);
		return (err);
	}
	if (strlen(xendev->otherend) == 0 ||
	    !xenbus_exists_dir(xendev->otherend, "")) {
		xenbus_dev_fatal(xendev, X_ENOENT, "missing other end from %s",
		    xendev->nodename);
		kmem_free((void *)xendev->otherend,
		    strlen(xendev->otherend) + 1);
		xendev->otherend = NULL;
		return (X_ENOENT);
	}

	return (0);
}


static int
read_backend_details(struct xenbus_device *xendev)
{
	return (read_otherend_details(xendev, "backend-id", "backend"));
}


static int
read_frontend_details(struct xenbus_device *xendev)
{
	return (read_otherend_details(xendev, "frontend-id", "frontend"));
}


static void
free_otherend_details(struct xenbus_device *dev)
{
	if (dev->otherend != NULL) {
		kmem_free((void *)dev->otherend, strlen(dev->otherend) + 1);
		dev->otherend = NULL;
	}
}


static void
free_otherend_watch(struct xenbus_device *dev)
{
	if (dev->otherend_watch.node) {
		unregister_xenbus_watch(&dev->otherend_watch);
		kmem_free((void *)dev->otherend_watch.node,
		    strlen(dev->otherend_watch.node) + 1);
		dev->otherend_watch.node = NULL;
	}
}


/*ARGSUSED2*/
static void
otherend_changed(struct xenbus_watch *watch, const char **vec, unsigned int len)
{
	struct xenbus_device *dev = watch->dev;
	XenbusState state;

	/*
	 * Protect us against watches firing on old details when the otherend
	 * details change, say immediately after a resume.
	 */
	if (!dev->otherend ||
	    strncmp(dev->otherend, vec[XS_WATCH_PATH], strlen(dev->otherend))) {
#if 0
		printf("Ignoring watch at %s", vec[XS_WATCH_PATH]);
#endif
		return;
	}

	state = xenbus_read_driver_state(dev->otherend);

#if 0
	printf("state is %d, %s, %s",
	    state, dev->otherend_watch.node, vec[XS_WATCH_PATH]);
#endif
	if (dev->otherend_changed)
		dev->otherend_changed(dev, state);
}


int
talk_to_otherend(struct xenbus_device *dev)
{
	int err;

	free_otherend_watch(dev);
	free_otherend_details(dev);

	if (dev->frontend)
		err = read_backend_details(dev);
	else
		err = read_frontend_details(dev);
	if (err)
		return (err);

	dev->otherend_watch.dev = dev;
	return (xenbus_watch_path2(dev, dev->otherend, "state",
	    &dev->otherend_watch, otherend_changed));
}


/*
 * Local variables:
 *  c-file-style: "solaris"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
