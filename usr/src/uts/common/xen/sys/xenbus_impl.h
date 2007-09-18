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
 *
 * xenbus.h (renamed to xenbus_impl.h)
 *
 * Talks to Xen Store to figure out what devices we have.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
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

#ifndef _SYS_XENBUS_H
#define	_SYS_XENBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mutex.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	XBT_NULL 0

typedef uint32_t xenbus_transaction_t;

/* Register callback to watch this node. */
struct xenbus_watch
{
	list_t list;
	const char *node;	/* path being watched */
	void (*callback)(struct xenbus_watch *,
			const char **vec,  unsigned int len);
	struct xenbus_device *dev;
};

/*
 * Call this function when xenstore is available, i.e. the daemon is
 * connected to the xenbus device.
 */
struct xenbus_notify {
	list_t list;
	void (*notify_func) (int);
};

/* A xenbus device. */
struct xenbus_device {
	const char *devicetype;
	const char *nodename;
	const char *otherend;
	int otherend_id;
	int otherend_state;
	struct xenbus_watch otherend_watch;
	int has_error;
	int frontend;
	void (*otherend_changed)(struct xenbus_device *, XenbusState);
	void *data;
};


extern char **xenbus_directory(xenbus_transaction_t t, const char *dir,
	    const char *node, unsigned int *num);
extern int xenbus_read(xenbus_transaction_t t, const char *dir,
	    const char *node, void **rstr, unsigned int *len);
extern int xenbus_write(xenbus_transaction_t t, const char *dir,
	    const char *node, const char *string);
extern int xenbus_mkdir(xenbus_transaction_t t, const char *dir,
	    const char *node);
extern int xenbus_exists(xenbus_transaction_t t, const char *dir,
	    const char *node);
extern int xenbus_rm(xenbus_transaction_t t, const char *dir,
	    const char *node);
extern int xenbus_transaction_start(xenbus_transaction_t *t);
extern int xenbus_transaction_end(xenbus_transaction_t t, int abort);

/* Single read and scanf: returns errno or num scanned if > 0. */
extern int xenbus_scanf(xenbus_transaction_t t, const char *dir,
	    const char *node, const char *fmt, ...);

/* Single printf and write: returns errno or 0. */
extern int xenbus_printf(xenbus_transaction_t t, const char *dir,
	    const char *node, const char *fmt, ...);

/*
 * Generic read function: NULL-terminated triples of name,
 * sprintf-style type string, and pointer. Returns 0 or errno.
 */
extern int xenbus_gather(xenbus_transaction_t t, const char *dir, ...);

extern int register_xenbus_watch(struct xenbus_watch *watch);
extern void unregister_xenbus_watch(struct xenbus_watch *watch);
extern void reregister_xenbus_watches(void);

/* Called from xen core code. */
extern void xenbus_suspend(void);
extern void xenbus_resume(void);

#define	XENBUS_EXIST_ERR(err) ((err) == ENOENT || (err) == ERANGE)

/*
 * Register a watch on the given path, using the given xenbus_watch structure
 * for storage, and the given callback function as the callback.  Return 0 on
 * success, or errno on error.  On success, the given path will be saved as
 * watch->node, and remains the caller's to free.  On error, watch->node will
 * be NULL, the device will switch to XenbusStateClosing, and the error will
 * be saved in the store.
 */
extern int xenbus_watch_path(struct xenbus_device *dev, const char *path,
			struct xenbus_watch *watch,
			void (*callback)(struct xenbus_watch *,
			const char **, unsigned int));


/*
 * Register a watch on the given path/path2, using the given xenbus_watch
 * structure for storage, and the given callback function as the callback.
 * Return 0 on success, or errno on error.  On success, the watched path
 * (path/path2) will be saved as watch->node, and becomes the caller's to
 * kfree().  On error, watch->node will be NULL, so the caller has nothing to
 * free, the device will switch to XenbusStateClosing, and the error will be
 * saved in the store.
 */
extern int xenbus_watch_path2(struct xenbus_device *dev, const char *path,
			const char *path2, struct xenbus_watch *watch,
			void (*callback)(struct xenbus_watch *,
			const char **, unsigned int));


/*
 * Advertise in the store a change of the given driver to the given new_state.
 * Perform the change inside the given transaction xbt.  xbt may be NULL, in
 * which case this is performed inside its own transaction.  Return 0 on
 * success, or errno on error.  On error, the device will switch to
 * XenbusStateClosing, and the error will be saved in the store.
 */
extern int xenbus_switch_state(struct xenbus_device *dev,
			xenbus_transaction_t xbt,
			XenbusState new_state);


/*
 * Grant access to the given ring_mfn to the peer of the given device.  Return
 * 0 on success, or errno on error.  On error, the device will switch to
 * XenbusStateClosing, and the error will be saved in the store.
 */
extern int xenbus_grant_ring(struct xenbus_device *dev, unsigned long ring_mfn);


/*
 * Allocate an event channel for the given xenbus_device, assigning the newly
 * created local port to *port.  Return 0 on success, or errno on error.  On
 * error, the device will switch to XenbusStateClosing, and the error will be
 * saved in the store.
 */
extern int xenbus_alloc_evtchn(struct xenbus_device *dev, int *port);


/*
 * Return the state of the driver rooted at the given store path, or
 * XenbusStateClosed if no state can be read.
 */
extern XenbusState xenbus_read_driver_state(const char *path);


/*
 * Report the given negative errno into the store, along with the given
 * formatted message.
 */
extern void xenbus_dev_error(struct xenbus_device *dev, int err,
	const char *fmt, ...);


/*
 * Equivalent to xenbus_dev_error(dev, err, fmt, args), followed by
 * xenbus_switch_state(dev, NULL, XenbusStateClosing) to schedule an orderly
 * closedown of this driver and its peer.
 */
extern void xenbus_dev_fatal(struct xenbus_device *dev,
	int err, const char *fmt, ...);

/* Clear any error. */
extern void xenbus_dev_ok(struct xenbus_device *dev);

/*
 * Set up watches on other end of split device.
 */
extern int talk_to_otherend(struct xenbus_device *dev);

#define	XENSTORE_DOWN	0	/* xenstore is down */
#define	XENSTORE_UP	1	/* xenstore is up */

/*
 * Register a notify callback function.
 */
extern int xs_register_xenbus_callback(void (*callback)(int));

/*
 * Notify clients that xenstore is up
 */
extern void xs_notify_xenstore_up(void);

/*
 * Notify clients that xenstore is down
 */
extern void xs_notify_xenstore_down(void);

struct xsd_sockmsg;

extern int xenbus_dev_request_and_reply(struct xsd_sockmsg *, void **);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_XENBUS_H */
