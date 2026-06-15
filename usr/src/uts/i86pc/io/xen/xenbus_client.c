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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Client-facing interface for the Xenbus driver.  In other words, the
 * interface between the Xenbus and the device-specific code, be it the
 * frontend or the backend of that driver.
 *
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
#include <sys/hypervisor.h>
#else
#include <sys/hypervisor.h>
#include <sys/xen_mmu.h>
#include <sys/evtchn_impl.h>
#endif
#include <sys/gnttab.h>
#include <xen/sys/xenbus_impl.h>
#include <sys/cmn_err.h>


int
xenbus_watch_path(struct xenbus_device *dev, const char *path,
    struct xenbus_watch *watch,
    void (*callback)(struct xenbus_watch *,
    const char **, unsigned int))
{
	int err;

	watch->node = path;
	watch->callback = callback;

	err = register_xenbus_watch(watch);

	if (err) {
		watch->node = NULL;
		watch->callback = NULL;
		xenbus_dev_fatal(dev, err, "adding watch on %s", path);
	}

	return (err);
}


int
xenbus_watch_path2(struct xenbus_device *dev, const char *path,
    const char *path2, struct xenbus_watch *watch,
    void (*callback)(struct xenbus_watch *,
    const char **, unsigned int))
{
	int err;
	char *state;

	state = kmem_alloc(strlen(path) + 1 + strlen(path2) + 1, KM_SLEEP);
	(void) strcpy(state, path);
	(void) strcat(state, "/");
	(void) strcat(state, path2);

	err = xenbus_watch_path(dev, state, watch, callback);
	if (err)
		kmem_free(state, strlen(state) + 1);
	return (err);
}

/*
 * Returns 0 on success, -1 if no change was made, or an errno on failure.  We
 * check whether the state is currently set to the given value, and if not,
 * then the state is set.  We don't want to unconditionally write the given
 * state, because we don't want to fire watches unnecessarily.  Furthermore, if
 * the node has gone, we don't write to it, as the device will be tearing down,
 * and we don't want to resurrect that directory.
 *
 * XXPV: not clear that this is still safe if two threads are racing to update
 * the state?
 */
int
xenbus_switch_state(struct xenbus_device *dev, xenbus_transaction_t xbt,
    XenbusState state)
{
	int current_state;
	int err;

	err = xenbus_scanf(xbt, dev->nodename, "state", "%d", &current_state);

	/* XXPV: is this really the right thing to do? */
	if (err == ENOENT)
		return (0);
	if (err)
		return (err);

	err = -1;

	if ((XenbusState)current_state != state) {
		err = xenbus_printf(xbt, dev->nodename, "state", "%d", state);
		if (err)
			xenbus_dev_fatal(dev, err, "writing new state");
	}

	return (err);
}


/*
 * Return the path to the error node for the given device, or NULL on failure.
 * If the value returned is non-NULL, then it is the caller's to kmem_free.
 */
static char *
error_path(struct xenbus_device *dev)
{
	char *path_buffer;

	path_buffer = kmem_alloc(strlen("error/") + strlen(dev->nodename) +
	    1, KM_SLEEP);

	(void) strcpy(path_buffer, "error/");
	(void) strcpy(path_buffer + strlen("error/"), dev->nodename);

	return (path_buffer);
}

static void
common_dev_error(struct xenbus_device *dev, int err, const char *fmt,
    va_list ap)
{
	int ret;
	unsigned int len;
	char *printf_buffer = NULL, *path_buffer = NULL;

#define	PRINTF_BUFFER_SIZE 4096
	printf_buffer = kmem_alloc(PRINTF_BUFFER_SIZE, KM_SLEEP);

	(void) snprintf(printf_buffer, PRINTF_BUFFER_SIZE, "%d ", err);
	len = strlen(printf_buffer);
	ret = vsnprintf(printf_buffer+len, PRINTF_BUFFER_SIZE-len, fmt, ap);

	ASSERT(len + ret <= PRINTF_BUFFER_SIZE-1);
	dev->has_error = 1;

	path_buffer = error_path(dev);

	if (path_buffer == NULL) {
		printf("xenbus: failed to write error node for %s (%s)\n",
		    dev->nodename, printf_buffer);
		goto fail;
	}

	if (xenbus_write(0, path_buffer, "error", printf_buffer) != 0) {
		printf("xenbus: failed to write error node for %s (%s)\n",
		    dev->nodename, printf_buffer);
		goto fail;
	}

fail:
	if (printf_buffer)
		kmem_free(printf_buffer, PRINTF_BUFFER_SIZE);
	if (path_buffer)
		kmem_free(path_buffer, strlen(path_buffer) + 1);
}


void
xenbus_dev_error(struct xenbus_device *dev, int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	common_dev_error(dev, err, fmt, ap);
	va_end(ap);
}


void
xenbus_dev_fatal(struct xenbus_device *dev, int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	common_dev_error(dev, err, fmt, ap);
	va_end(ap);

	(void) xenbus_switch_state(dev, XBT_NULL, XenbusStateClosing);
}

/* Clear any error. */
void
xenbus_dev_ok(struct xenbus_device *dev)
{
	if (dev->has_error) {
		if (xenbus_rm(0, dev->nodename, "error") != 0)
			printf("xenbus: failed to clear error node for %s\n",
			    dev->nodename);
		else
			dev->has_error = 0;
	}
}

int
xenbus_grant_ring(struct xenbus_device *dev, unsigned long ring_mfn)
{
	int err = gnttab_grant_foreign_access(dev->otherend_id, ring_mfn, 0);
	if (err < 0)
		xenbus_dev_fatal(dev, err, "granting access to ring page");
	return (err);
}


int
xenbus_alloc_evtchn(struct xenbus_device *dev, int *port)
{
	int err;

	err = xen_alloc_unbound_evtchn(dev->otherend_id, port);
	if (err)
		xenbus_dev_fatal(dev, err, "allocating event channel");
	return (err);
}


XenbusState
xenbus_read_driver_state(const char *path)
{
	XenbusState result;

	int err = xenbus_gather(XBT_NULL, path, "state", "%d", &result, NULL);
	if (err)
		result = XenbusStateClosed;

	return (result);
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
