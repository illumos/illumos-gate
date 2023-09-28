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
 *
 * xenbus_xs.c
 *
 * This is the kernel equivalent of the "xs" library.  We don't need everything
 * and we use xenbus_comms for communication.
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

/*
 * NOTE: To future maintainers of the Solaris version of this file:
 * I found the Linux version of this code to be very disgusting in
 * overloading pointers and error codes into void * return values.
 * The main difference you will find is that all such usage is changed
 * to pass pointers to void* to be filled in with return values and
 * the functions return error codes.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/rwlock.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/avintr.h>
#include <sys/cmn_err.h>
#include <sys/mach_mmu.h>
#include <util/sscanf.h>
#define	_XSD_ERRORS_DEFINED
#ifdef XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#endif
#include <sys/hypervisor.h>
#include <sys/taskq.h>
#include <sys/sdt.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/sys/xendev.h>
#include <xen/public/io/xs_wire.h>

#define	streq(a, b) (strcmp((a), (b)) == 0)

#define	list_empty(list) (list_head(list) == NULL)

struct xs_stored_msg {
	list_node_t list;

	struct xsd_sockmsg hdr;

	union {
		/* Queued replies. */
		struct {
			char *body;
		} reply;

		/* Queued watch events. */
		struct {
			struct xenbus_watch *handle;
			char **vec;
			unsigned int vec_size;
		} watch;
	} un;
};

static struct xs_handle {
	/* A list of replies. Currently only one will ever be outstanding. */
	list_t reply_list;
	kmutex_t reply_lock;
	kcondvar_t reply_cv;

	/* One request at a time. */
	kmutex_t request_mutex;

	/* Protect transactions against save/restore. */
	krwlock_t suspend_lock;
} xs_state;

static int last_req_id;

/*
 * List of clients wanting a xenstore up notification, and a lock to protect it
 */
static boolean_t xenstore_up;
static list_t notify_list;
static kmutex_t notify_list_lock;
static taskq_t *xenbus_taskq;

/* List of registered watches, and a lock to protect it. */
static list_t watches;
static kmutex_t watches_lock;

/* List of pending watch callback events, and a lock to protect it. */
static list_t watch_events;
static kmutex_t watch_events_lock;

/*
 * Details of the xenwatch callback kernel thread. The thread waits on the
 * watch_events_cv for work to do (queued on watch_events list). When it
 * wakes up it acquires the xenwatch_mutex before reading the list and
 * carrying out work.
 */
static kmutex_t xenwatch_mutex;
static kcondvar_t watch_events_cv;

static int process_msg(void);

static int
get_error(const char *errorstring)
{
	unsigned int i;

	for (i = 0; !streq(errorstring, xsd_errors[i].errstring); i++) {
		if (i == (sizeof (xsd_errors) / sizeof (xsd_errors[0])) - 1) {
			cmn_err(CE_WARN,
			    "XENBUS xen store gave: unknown error %s",
			    errorstring);
			return (EINVAL);
		}
	}
	return (xsd_errors[i].errnum);
}

/*
 * Read a synchronous reply from xenstore.  Since we can return early before
 * reading a relevant reply, we discard any messages not matching the request
 * ID.  Caller must free returned message on success.
 */
static int
read_reply(struct xsd_sockmsg *req_hdr, struct xs_stored_msg **reply)
{
	extern int do_polled_io;

	mutex_enter(&xs_state.reply_lock);

	for (;;) {
		while (list_empty(&xs_state.reply_list)) {
			if (interrupts_unleashed && !do_polled_io) {
				if (cv_wait_sig(&xs_state.reply_cv,
				    &xs_state.reply_lock) == 0) {
					mutex_exit(&xs_state.reply_lock);
					*reply = NULL;
					return (EINTR);
				}
			} else { /* polled mode needed for early probes */
				mutex_exit(&xs_state.reply_lock);
				(void) HYPERVISOR_yield();
				(void) process_msg();
				mutex_enter(&xs_state.reply_lock);
			}
		}

		*reply = list_head(&xs_state.reply_list);
		list_remove(&xs_state.reply_list, *reply);

		if ((*reply)->hdr.req_id == req_hdr->req_id)
			break;
	}

	mutex_exit(&xs_state.reply_lock);
	return (0);
}

/* Emergency write. */
void
xenbus_debug_write(const char *str, unsigned int count)
{
	struct xsd_sockmsg msg = { 0 };

	msg.type = XS_DEBUG;
	msg.len = sizeof ("print") + count + 1;

	mutex_enter(&xs_state.request_mutex);
	(void) xb_write(&msg, sizeof (msg));
	(void) xb_write("print", sizeof ("print"));
	(void) xb_write(str, count);
	(void) xb_write("", 1);
	mutex_exit(&xs_state.request_mutex);
}

/*
 * This is pretty unpleasant.  First off, there's the horrible logic around
 * suspend_lock and transactions.  Also, we can be interrupted either before we
 * write a message, or before we receive a reply.  A client that wants to
 * survive this can't know which case happened.  Luckily all clients don't care
 * about signals currently, and the alternative (a hard wait on a userspace
 * daemon) isn't exactly preferable.  Caller must free 'reply' on success.
 */
int
xenbus_dev_request_and_reply(struct xsd_sockmsg *msg, void **reply)
{
	struct xsd_sockmsg req_msg = *msg;
	struct xs_stored_msg *reply_msg = NULL;
	int err;

	if (req_msg.type == XS_TRANSACTION_START)
		rw_enter(&xs_state.suspend_lock, RW_READER);

	mutex_enter(&xs_state.request_mutex);

	msg->req_id = last_req_id++;

	err = xb_write(msg, sizeof (*msg) + msg->len);
	if (err) {
		if (req_msg.type == XS_TRANSACTION_START)
			rw_exit(&xs_state.suspend_lock);
		msg->type = XS_ERROR;
		*reply = NULL;
		goto out;
	}

	err = read_reply(msg, &reply_msg);

	if (err) {
		if (msg->type == XS_TRANSACTION_START)
			rw_exit(&xs_state.suspend_lock);
		*reply = NULL;
		goto out;
	}

	*reply = reply_msg->un.reply.body;
	*msg = reply_msg->hdr;

	if (reply_msg->hdr.type == XS_TRANSACTION_END)
		rw_exit(&xs_state.suspend_lock);

out:
	if (reply_msg != NULL)
		kmem_free(reply_msg, sizeof (*reply_msg));

	mutex_exit(&xs_state.request_mutex);
	return (err);
}

/*
 * Send message to xs, return errcode, rval filled in with pointer
 * to kmem_alloc'ed reply.
 */
static int
xs_talkv(xenbus_transaction_t t,
		    enum xsd_sockmsg_type type,
		    const iovec_t *iovec,
		    unsigned int num_vecs,
		    void **rval,
		    unsigned int *len)
{
	struct xsd_sockmsg msg;
	struct xs_stored_msg *reply_msg;
	char *reply;
	unsigned int i;
	int err;

	msg.tx_id = (uint32_t)(unsigned long)t;
	msg.type = type;
	msg.len = 0;
	for (i = 0; i < num_vecs; i++)
		msg.len += iovec[i].iov_len;

	mutex_enter(&xs_state.request_mutex);

	msg.req_id = last_req_id++;

	err = xb_write(&msg, sizeof (msg));
	if (err) {
		mutex_exit(&xs_state.request_mutex);
		return (err);
	}

	for (i = 0; i < num_vecs; i++) {
		err = xb_write(iovec[i].iov_base, iovec[i].iov_len);
		if (err) {
			mutex_exit(&xs_state.request_mutex);
			return (err);
		}
	}

	err = read_reply(&msg, &reply_msg);

	mutex_exit(&xs_state.request_mutex);

	if (err)
		return (err);

	reply = reply_msg->un.reply.body;

	if (reply_msg->hdr.type == XS_ERROR) {
		err = get_error(reply);
		kmem_free(reply, reply_msg->hdr.len + 1);
		goto out;
	}

	if (len != NULL)
		*len = reply_msg->hdr.len + 1;

	ASSERT(reply_msg->hdr.type == type);

	if (rval != NULL)
		*rval = reply;
	else
		kmem_free(reply, reply_msg->hdr.len + 1);

out:
	kmem_free(reply_msg, sizeof (*reply_msg));
	return (err);
}

/* Simplified version of xs_talkv: single message. */
static int
xs_single(xenbus_transaction_t t,
			enum xsd_sockmsg_type type,
			const char *string, void **ret,
			unsigned int *len)
{
	iovec_t iovec;

	iovec.iov_base = (char *)string;
	iovec.iov_len = strlen(string) + 1;
	return (xs_talkv(t, type, &iovec, 1, ret, len));
}

static unsigned int
count_strings(const char *strings, unsigned int len)
{
	unsigned int num;
	const char *p;

	for (p = strings, num = 0; p < strings + len; p += strlen(p) + 1)
		num++;

	return (num);
}

/* Return the path to dir with /name appended. Buffer must be kmem_free()'ed */
static char *
join(const char *dir, const char *name)
{
	char *buffer;
	size_t slashlen;

	slashlen = streq(name, "") ? 0 : 1;
	buffer = kmem_alloc(strlen(dir) + slashlen + strlen(name) + 1,
	    KM_SLEEP);

	(void) strcpy(buffer, dir);
	if (slashlen != 0) {
		(void) strcat(buffer, "/");
		(void) strcat(buffer, name);
	}
	return (buffer);
}

static char **
split(char *strings, unsigned int len, unsigned int *num)
{
	char *p, **ret;

	/* Count the strings. */
	if ((*num = count_strings(strings, len - 1)) == 0)
		return (NULL);

	/* Transfer to one big alloc for easy freeing. */
	ret = kmem_alloc(*num * sizeof (char *) + (len - 1), KM_SLEEP);
	(void) memcpy(&ret[*num], strings, len - 1);
	kmem_free(strings, len);

	strings = (char *)&ret[*num];
	for (p = strings, *num = 0; p < strings + (len - 1);
	    p += strlen(p) + 1) {
		ret[(*num)++] = p;
	}

	return (ret);
}

char **
xenbus_directory(xenbus_transaction_t t,
			const char *dir, const char *node, unsigned int *num)
{
	char *strings, *path;
	unsigned int len;
	int err;

	path = join(dir, node);
	err = xs_single(t, XS_DIRECTORY, path, (void **)&strings, &len);
	kmem_free(path, strlen(path) + 1);
	if (err != 0 || strings == NULL) {
		/* sigh, we lose error code info here */
		*num = 0;
		return (NULL);
	}

	return (split(strings, len, num));
}

/* Check if a path exists. */
boolean_t
xenbus_exists(const char *dir, const char *node)
{
	void	*p;
	uint_t	n;

	if (xenbus_read(XBT_NULL, dir, node, &p, &n) != 0)
		return (B_FALSE);
	kmem_free(p, n);
	return (B_TRUE);
}

/* Check if a directory path exists. */
boolean_t
xenbus_exists_dir(const char *dir, const char *node)
{
	char **d;
	unsigned int dir_n;
	int i, len;

	d = xenbus_directory(XBT_NULL, dir, node, &dir_n);
	if (d == NULL)
		return (B_FALSE);
	for (i = 0, len = 0; i < dir_n; i++)
		len += strlen(d[i]) + 1 + sizeof (char *);
	kmem_free(d, len);
	return (B_TRUE);
}

/*
 * Get the value of a single file.
 * Returns a kmem_alloced value in retp: call kmem_free() on it after use.
 * len indicates length in bytes.
 */
int
xenbus_read(xenbus_transaction_t t,
	    const char *dir, const char *node, void **retp, unsigned int *len)
{
	char *path;
	int err;

	path = join(dir, node);
	err = xs_single(t, XS_READ, path, retp, len);
	kmem_free(path, strlen(path) + 1);
	return (err);
}

int
xenbus_read_str(const char *dir, const char *node, char **retp)
{
	uint_t	n;
	int	err;
	char	*str;

	/*
	 * Since we access the xenbus value immediatly we can't be
	 * part of a transaction.
	 */
	if ((err = xenbus_read(XBT_NULL, dir, node, (void **)&str, &n)) != 0)
		return (err);
	ASSERT((str != NULL) && (n > 0));

	/*
	 * Why bother with this?  Because xenbus is truly annoying in the
	 * fact that when it returns a string, it doesn't guarantee that
	 * the memory that holds the string is of size strlen() + 1.
	 * This forces callers to keep track of the size of the memory
	 * containing the string.  Ugh.  We'll work around this by
	 * re-allocate strings to always be of size strlen() + 1.
	 */
	*retp = strdup(str);
	kmem_free(str, n);
	return (0);
}

/*
 * Write the value of a single file.
 * Returns err on failure.
 */
int
xenbus_write(xenbus_transaction_t t,
		const char *dir, const char *node, const char *string)
{
	char *path;
	iovec_t iovec[2];
	int ret;

	path = join(dir, node);

	iovec[0].iov_base = (void *)path;
	iovec[0].iov_len = strlen(path) + 1;
	iovec[1].iov_base = (void *)string;
	iovec[1].iov_len = strlen(string);

	ret = xs_talkv(t, XS_WRITE, iovec, 2, NULL, NULL);
	kmem_free(path, iovec[0].iov_len);
	return (ret);
}

/* Create a new directory. */
int
xenbus_mkdir(xenbus_transaction_t t, const char *dir, const char *node)
{
	char *path;
	int ret;

	path = join(dir, node);
	ret = xs_single(t, XS_MKDIR, path, NULL, NULL);
	kmem_free(path, strlen(path) + 1);
	return (ret);
}

/* Destroy a file or directory (directories must be empty). */
int
xenbus_rm(xenbus_transaction_t t, const char *dir, const char *node)
{
	char *path;
	int ret;

	path = join(dir, node);
	ret = xs_single(t, XS_RM, path, NULL, NULL);
	kmem_free(path, strlen(path) + 1);
	return (ret);
}

/*
 * Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 */
int
xenbus_transaction_start(xenbus_transaction_t *t)
{
	void *id_str;
	unsigned long id;
	int err;
	unsigned int len;

	rw_enter(&xs_state.suspend_lock, RW_READER);

	err = xs_single(XBT_NULL, XS_TRANSACTION_START, "", &id_str, &len);
	if (err) {
		rw_exit(&xs_state.suspend_lock);
		return (err);
	}

	(void) ddi_strtoul((char *)id_str, NULL, 0, &id);
	*t = (xenbus_transaction_t)id;
	kmem_free(id_str, len);

	return (0);
}

/*
 * End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 */
int
xenbus_transaction_end(xenbus_transaction_t t, int abort)
{
	char abortstr[2];
	int err;

	if (abort)
		(void) strcpy(abortstr, "F");
	else
		(void) strcpy(abortstr, "T");

	err = xs_single(t, XS_TRANSACTION_END, abortstr, NULL, NULL);

	rw_exit(&xs_state.suspend_lock);

	return (err);
}

/*
 * Single read and scanf: returns errno or 0.  This can only handle a single
 * conversion specifier.
 */
/* SCANFLIKE4 */
int
xenbus_scanf(xenbus_transaction_t t,
		const char *dir, const char *node, const char *fmt, ...)
{
	va_list ap;
	int ret;
	char *val;
	unsigned int len;

	ret = xenbus_read(t, dir, node, (void **)&val, &len);
	if (ret)
		return (ret);

	va_start(ap, fmt);
	if (vsscanf(val, fmt, ap) != 1)
		ret = ERANGE;
	va_end(ap);
	kmem_free(val, len);
	return (ret);
}

/* Single printf and write: returns errno or 0. */
/* PRINTFLIKE4 */
int
xenbus_printf(xenbus_transaction_t t,
		const char *dir, const char *node, const char *fmt, ...)
{
	va_list ap;
	int ret;
#define	PRINTF_BUFFER_SIZE 4096
	char *printf_buffer;

	printf_buffer = kmem_alloc(PRINTF_BUFFER_SIZE, KM_SLEEP);

	va_start(ap, fmt);
	ret = vsnprintf(printf_buffer, PRINTF_BUFFER_SIZE, fmt, ap);
	va_end(ap);

	ASSERT(ret <= PRINTF_BUFFER_SIZE-1);
	ret = xenbus_write(t, dir, node, printf_buffer);

	kmem_free(printf_buffer, PRINTF_BUFFER_SIZE);

	return (ret);
}


/* Takes tuples of names, scanf-style args, and void **, NULL terminated. */
int
xenbus_gather(xenbus_transaction_t t, const char *dir, ...)
{
	va_list ap;
	const char *name;
	int ret = 0;
	unsigned int len;

	va_start(ap, dir);
	while (ret == 0 && (name = va_arg(ap, char *)) != NULL) {
		const char *fmt = va_arg(ap, char *);
		void *result = va_arg(ap, void *);
		char *p;

		ret = xenbus_read(t, dir, name, (void **)&p, &len);
		if (ret)
			break;
		if (fmt) {
			ASSERT(result != NULL);
			if (sscanf(p, fmt, result) != 1)
				ret = EINVAL;
			kmem_free(p, len);
		} else
			*(char **)result = p;
	}
	va_end(ap);
	return (ret);
}

static int
xs_watch(const char *path, const char *token)
{
	iovec_t iov[2];

	iov[0].iov_base = (void *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (void *)token;
	iov[1].iov_len = strlen(token) + 1;

	return (xs_talkv(XBT_NULL, XS_WATCH, iov, 2, NULL, NULL));
}

static int
xs_unwatch(const char *path, const char *token)
{
	iovec_t iov[2];

	iov[0].iov_base = (char *)path;
	iov[0].iov_len = strlen(path) + 1;
	iov[1].iov_base = (char *)token;
	iov[1].iov_len = strlen(token) + 1;

	return (xs_talkv(XBT_NULL, XS_UNWATCH, iov, 2, NULL, NULL));
}

static struct xenbus_watch *
find_watch(const char *token)
{
	struct xenbus_watch *i, *cmp;

	(void) ddi_strtoul(token, NULL, 16, (unsigned long *)&cmp);

	for (i = list_head(&watches); i != NULL; i = list_next(&watches, i))
		if (i == cmp)
			break;

	return (i);
}

/* Register a xenstore state notify callback */
int
xs_register_xenbus_callback(void (*callback)(int))
{
	struct xenbus_notify *xbn, *xnp;

	xbn = kmem_alloc(sizeof (struct xenbus_notify), KM_SLEEP);
	xbn->notify_func = callback;
	mutex_enter(&notify_list_lock);
	/*
	 * Make sure not already on the list
	 */
	xnp = list_head(&notify_list);
	for (; xnp != NULL; xnp = list_next(&notify_list, xnp)) {
		if (xnp->notify_func == callback) {
			kmem_free(xbn, sizeof (struct xenbus_notify));
			mutex_exit(&notify_list_lock);
			return (EEXIST);
		}
	}
	xnp = xbn;
	list_insert_tail(&notify_list, xbn);
	if (xenstore_up)
		xnp->notify_func(XENSTORE_UP);
	mutex_exit(&notify_list_lock);
	return (0);
}

/*
 * Notify clients of xenstore state
 */
static void
do_notify_callbacks(void *arg)
{
	struct xenbus_notify *xnp;

	mutex_enter(&notify_list_lock);
	xnp = list_head(&notify_list);
	for (; xnp != NULL; xnp = list_next(&notify_list, xnp)) {
		xnp->notify_func((int)((uintptr_t)arg));
	}
	mutex_exit(&notify_list_lock);
}

void
xs_notify_xenstore_up(void)
{
	xenstore_up = B_TRUE;
	(void) taskq_dispatch(xenbus_taskq, do_notify_callbacks,
	    (void *)XENSTORE_UP, 0);
}

void
xs_notify_xenstore_down(void)
{
	xenstore_up = B_FALSE;
	(void) taskq_dispatch(xenbus_taskq, do_notify_callbacks,
	    (void *)XENSTORE_DOWN, 0);
}

/* Register callback to watch this node. */
int
register_xenbus_watch(struct xenbus_watch *watch)
{
	/* Pointer in ascii is the token. */
	char token[sizeof (watch) * 2 + 1];
	int err;

	ASSERT(xenstore_up);
	(void) snprintf(token, sizeof (token), "%lX", (long)watch);

	rw_enter(&xs_state.suspend_lock, RW_READER);

	mutex_enter(&watches_lock);
	/*
	 * May be re-registering a watch if xenstore daemon was restarted
	 */
	if (find_watch(token) == NULL)
		list_insert_tail(&watches, watch);
	mutex_exit(&watches_lock);

	DTRACE_XPV3(xenbus__register__watch, const char *, watch->node,
	    uintptr_t, watch->callback, struct xenbus_watch *, watch);

	err = xs_watch(watch->node, token);

	/* Ignore errors due to multiple registration. */
	if ((err != 0) && (err != EEXIST)) {
		mutex_enter(&watches_lock);
		list_remove(&watches, watch);
		mutex_exit(&watches_lock);
	}

	rw_exit(&xs_state.suspend_lock);

	return (err);
}

static void
free_stored_msg(struct xs_stored_msg *msg)
{
	int i, len = 0;

	for (i = 0; i < msg->un.watch.vec_size; i++)
		len += strlen(msg->un.watch.vec[i]) + 1 + sizeof (char *);
	kmem_free(msg->un.watch.vec, len);
	kmem_free(msg, sizeof (*msg));
}

void
unregister_xenbus_watch(struct xenbus_watch *watch)
{
	struct xs_stored_msg *msg;
	char token[sizeof (watch) * 2 + 1];
	int err;

	(void) snprintf(token, sizeof (token), "%lX", (long)watch);

	rw_enter(&xs_state.suspend_lock, RW_READER);

	mutex_enter(&watches_lock);
	ASSERT(find_watch(token));
	list_remove(&watches, watch);
	mutex_exit(&watches_lock);

	DTRACE_XPV3(xenbus__unregister__watch, const char *, watch->node,
	    uintptr_t, watch->callback, struct xenbus_watch *, watch);

	err = xs_unwatch(watch->node, token);
	if (err)
		cmn_err(CE_WARN, "XENBUS Failed to release watch %s: %d",
		    watch->node, err);

	rw_exit(&xs_state.suspend_lock);

	/* Cancel pending watch events. */
	mutex_enter(&watch_events_lock);
	msg = list_head(&watch_events);

	while (msg != NULL) {
		struct xs_stored_msg *tmp = list_next(&watch_events, msg);
		if (msg->un.watch.handle == watch) {
			list_remove(&watch_events, msg);
			free_stored_msg(msg);
		}
		msg = tmp;
	}

	mutex_exit(&watch_events_lock);

	/* Flush any currently-executing callback, unless we are it. :-) */
	if (mutex_owner(&xenwatch_mutex) != curthread) {
		mutex_enter(&xenwatch_mutex);
		mutex_exit(&xenwatch_mutex);
	}
}

void
xenbus_suspend(void)
{
	rw_enter(&xs_state.suspend_lock, RW_WRITER);
	mutex_enter(&xs_state.request_mutex);

	xb_suspend();
}

void
xenbus_resume(void)
{
	struct xenbus_watch *watch;
	char token[sizeof (watch) * 2 + 1];

	mutex_exit(&xs_state.request_mutex);

	xb_init();
	xb_setup_intr();

	/* No need for watches_lock: the suspend_lock is sufficient. */
	for (watch = list_head(&watches); watch != NULL;
	    watch = list_next(&watches, watch)) {
		(void) snprintf(token, sizeof (token), "%lX", (long)watch);
		(void) xs_watch(watch->node, token);
	}

	rw_exit(&xs_state.suspend_lock);
}

static void
xenwatch_thread(void)
{
	struct xs_stored_msg *msg;
	struct xenbus_watch *watch;

	for (;;) {
		mutex_enter(&watch_events_lock);
		while (list_empty(&watch_events))
			cv_wait(&watch_events_cv, &watch_events_lock);
		msg = list_head(&watch_events);
		ASSERT(msg != NULL);
		list_remove(&watch_events, msg);
		watch = msg->un.watch.handle;
		mutex_exit(&watch_events_lock);

		mutex_enter(&xenwatch_mutex);

		DTRACE_XPV4(xenbus__fire__watch,
		    const char *, watch->node,
		    uintptr_t, watch->callback,
		    struct xenbus_watch *, watch,
		    const char *, msg->un.watch.vec[XS_WATCH_PATH]);

		watch->callback(watch, (const char **)msg->un.watch.vec,
		    msg->un.watch.vec_size);

		free_stored_msg(msg);
		mutex_exit(&xenwatch_mutex);
	}
}

static int
process_msg(void)
{
	struct xs_stored_msg *msg;
	char *body;
	int err, mlen;

	msg = kmem_alloc(sizeof (*msg), KM_SLEEP);

	err = xb_read(&msg->hdr, sizeof (msg->hdr));
	if (err) {
		kmem_free(msg, sizeof (*msg));
		return (err);
	}

	mlen = msg->hdr.len + 1;
	body = kmem_alloc(mlen, KM_SLEEP);

	err = xb_read(body, msg->hdr.len);
	if (err) {
		kmem_free(body, mlen);
		kmem_free(msg, sizeof (*msg));
		return (err);
	}

	body[mlen - 1] = '\0';

	if (msg->hdr.type == XS_WATCH_EVENT) {
		const char *token;
		msg->un.watch.vec = split(body, msg->hdr.len + 1,
		    &msg->un.watch.vec_size);
		if (msg->un.watch.vec == NULL) {
			kmem_free(msg, sizeof (*msg));
			return (EIO);
		}

		mutex_enter(&watches_lock);
		token = msg->un.watch.vec[XS_WATCH_TOKEN];
		if ((msg->un.watch.handle = find_watch(token)) != NULL) {
			mutex_enter(&watch_events_lock);

			DTRACE_XPV4(xenbus__enqueue__watch,
			    const char *, msg->un.watch.handle->node,
			    uintptr_t, msg->un.watch.handle->callback,
			    struct xenbus_watch *, msg->un.watch.handle,
			    const char *, msg->un.watch.vec[XS_WATCH_PATH]);

			list_insert_tail(&watch_events, msg);
			cv_broadcast(&watch_events_cv);
			mutex_exit(&watch_events_lock);
		} else {
			free_stored_msg(msg);
		}
		mutex_exit(&watches_lock);
	} else {
		msg->un.reply.body = body;
		mutex_enter(&xs_state.reply_lock);
		list_insert_tail(&xs_state.reply_list, msg);
		mutex_exit(&xs_state.reply_lock);
		cv_signal(&xs_state.reply_cv);
	}

	return (0);
}

static void
xenbus_thread(void)
{
	int err;

	/*
	 * We have to wait for interrupts to be ready, so we don't clash
	 * with the polled-IO code in read_reply().
	 */
	while (!interrupts_unleashed)
		delay(10);

	for (;;) {
		err = process_msg();
		if (err)
			cmn_err(CE_WARN, "XENBUS error %d while reading "
			    "message", err);
	}
}

/*
 * When setting up xenbus, dom0 and domU have to take different paths, which
 * makes this code a little confusing. For dom0:
 *
 * xs_early_init - mutex init only
 * xs_dom0_init - called on xenbus dev attach: set up our xenstore page and
 * event channel; start xenbus threads for responding to interrupts.
 *
 * And for domU:
 *
 * xs_early_init - mutex init; set up our xenstore page and event channel
 * xs_domu_init - installation of IRQ handler; start xenbus threads.
 *
 * We need an early init on domU so we can use xenbus in polled mode to
 * discover devices, VCPUs etc.
 *
 * On resume, we use xb_init() and xb_setup_intr() to restore xenbus to a
 * working state.
 */

void
xs_early_init(void)
{
	list_create(&xs_state.reply_list, sizeof (struct xs_stored_msg),
	    offsetof(struct xs_stored_msg, list));
	list_create(&watch_events, sizeof (struct xs_stored_msg),
	    offsetof(struct xs_stored_msg, list));
	list_create(&watches, sizeof (struct xenbus_watch),
	    offsetof(struct xenbus_watch, list));
	list_create(&notify_list, sizeof (struct xenbus_notify),
	    offsetof(struct xenbus_notify, list));
	mutex_init(&xs_state.reply_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&xs_state.request_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&notify_list_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&xs_state.suspend_lock, NULL, RW_DEFAULT, NULL);
	cv_init(&xs_state.reply_cv, NULL, CV_DEFAULT, NULL);

	if (DOMAIN_IS_INITDOMAIN(xen_info))
		return;

	xb_init();
	xenstore_up = B_TRUE;
}

static void
xs_thread_init(void)
{
	(void) thread_create(NULL, 0, xenwatch_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
	(void) thread_create(NULL, 0, xenbus_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
	xenbus_taskq = taskq_create("xenbus_taskq", 1,
	    maxclsyspri - 1, 1, 1, TASKQ_PREPOPULATE);
	ASSERT(xenbus_taskq != NULL);
}

void
xs_domu_init(void)
{
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		return;

	/*
	 * Add interrupt handler for xenbus now, must wait till after
	 * psm module is loaded.  All use of xenbus is in polled mode
	 * until xs_init is called since it is what kicks off the xs
	 * server threads.
	 */
	xs_thread_init();
	xb_setup_intr();
}


void
xs_dom0_init(void)
{
	static boolean_t initialized = B_FALSE;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	/*
	 * The xenbus driver might be re-attaching.
	 */
	if (initialized)
		return;

	xb_init();
	xs_thread_init();
	xb_setup_intr();

	initialized = B_TRUE;
}
