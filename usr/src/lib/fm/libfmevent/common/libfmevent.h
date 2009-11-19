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

#ifndef _LIBFMEVENT_H
#define	_LIBFMEVENT_H

/*
 * FMA event library.
 *
 * A. Protocol event subscription interfaces (Committed).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libnvpair.h>
#include <stdlib.h>
#include <door.h>
#include <sys/time.h>
#include <sys/fm/protocol.h>

/*
 * Library ABI interface version.  Quote the version you are using
 * to fmev_shdl_init.  Only interfaces introduced in or prior to the
 * quoted version will be available.  Once introduced an interface
 * only ever changes compatibly.
 */
#define	LIBFMEVENT_VERSION_1	1

#define	LIBFMEVENT_VERSION_LATEST	LIBFMEVENT_VERSION_1

/*
 * Success and error return values.  The descriptive comment for each
 * FMEVERR_* becomes the string that is returned by fmev_strerror for that
 * error type.
 */
typedef enum {
    FMEV_SUCCESS = 0,
    FMEV_OK = FMEV_SUCCESS, /* alias for FMEV_SUCCESS */
    FMEVERR_UNKNOWN = 0xe000, /* Error details unknown */
    FMEVERR_VERSION_MISMATCH, /* Library ABI version incompatible with caller */
    FMEVERR_API, /* Library API usage violation */
    FMEVERR_ALLOC, /* Failed to allocate additional resources */
    FMEVERR_MALFORMED_EVENT, /* Event contents are inconsistent or corrupt */
    FMEVERR_OVERFLOW, /* Operation would overflow result type */
    FMEVERR_INTERNAL, /* Internal library error */
    FMEVERR_NOPRIV, /* Insufficient permissions or privilege */
    FMEVERR_BUSY, /* Resource is busy */
    FMEVERR_DUPLICATE, /* Duplicate request */
    FMEVERR_BADCLASS, /* Bad event class or class pattern */
    FMEVERR_NOMATCH, /* No match to criteria provided */
    FMEVERR_MAX_SUBSCRIBERS, /* Exceeds maximum subscribers per handle */
    FMEVERR_INVALIDARG /* Argument is invalid */
} fmev_err_t;

/*
 * Some interfaces return an fmev_err_t - FMEV_SUCCESS on success, otherwise
 * failure of the indicated type.  You can use fmev_strerror to render an
 * fmev_err_t into a string.
 *
 * Other interfaces do not return an fmev_err_t directly.  For example
 * where we return a pointer an error is indicated by a NULL return.
 * In these cases you can retrieve the fmev_err_t describing the reason
 * for the failure using fmev_errno or get a string with
 * fmev_strerr(fmev_errno).  Note that fmev_errno is per-thread and holds
 * the error value for any error that occured during the last libfmevent
 * API call made by the current thread.  Use fmev_errno as you would
 * regular errno, but you should not assign to fmev_errno.
 */
extern const fmev_err_t *__fmev_errno(void);	/* do not use this directly */
#define	fmev_errno (*(__fmev_errno()))
extern const char *fmev_strerror(fmev_err_t);

/*
 * Part A - Protocol Event Subscription
 * ======
 *
 * Subscribe to FMA protocol events published by the fault management
 * daemon, receiving a callback for each matching event.
 *
 * This is a Committed interface (see attributes(5) for a definition).
 */

/*
 * Opaque subscription handle and event types.
 */
typedef struct fmev_shdl *fmev_shdl_t;
typedef struct fmev *fmev_t;

/*
 * Subscription callback function type for fmev_shdl_subscribe.
 */
typedef void fmev_cbfunc_t(fmev_t, const char *, nvlist_t *, void *);

/*
 * Initialize a new handle using fmev_shdl_init and quoting interface
 * version number along with alloc, zalloc and free function pointers (all
 * NULL to use the defaults.
 *
 * Close the handle and release resources with fmev_shdl_fini.
 */

extern fmev_shdl_t fmev_shdl_init(uint32_t,
    void *(*)(size_t),		/* alloc */
    void *(*)(size_t),		/* zalloc */
    void (*)(void *, size_t));	/* free */

extern fmev_err_t fmev_shdl_fini(fmev_shdl_t);

/*
 * Having created a handle you may optionally configure various properties
 * for this handle using fmev_shdlctl_*.  In most cases accepting the defaults
 * (that are obtained through fmev_shdl_init alone) will provide adequate
 * semantics - the controls below are provided for applications
 * that require fine-grained control over event delivery semantics and, in
 * particular, the service threads used to perform delivery callbacks.
 *
 * These controls may only be applied to a subscription handle
 * that has no current subscriptions in place.  You therefore cannot
 * change the properties once subscriptions are established, and the
 * handle properties apply uniformly to all subscriptions on that handle.
 * If you require different properties per subscription then use multiple
 * handles.
 *
 * fmev_shdlctl_serialize() will serialize all callbacks arising from all
 * subscriptions on a handle.  Event deliveries are normally single-threaded
 * on a per-subscribtion bases, that is a call to fmev_shdl_subscribe
 * will have deliveries arising from that subscription delivered
 * in a serialized fashion on a single thread dedicated to the subscription.
 * If multiple subscriptions are established then each has a dedicated
 * delivery thread - fmev_shdlctl_serialize arranges that only one of these
 * threads services a callback at any one time.
 *
 * fmev_shdlctl_thrattr() allows you to provide thread attributes for use
 * in pthread_create() when server threads are created.  The attributes
 * are not copied - the pthread_attr_t object passed must exist for
 * the duration of all subscriptions on the handle.  These attributes only
 * apply if fmev_shdlctl_thrcreate() is not in use on this handle.
 *
 * fmev_shdlctl_sigmask() allows you to provide a sigset_t signal mask
 * of signals to block in server threads.  The pthread_sigmask is set
 * to this immediately before pthread_create, and restored immediately
 * after pthread_create.  This mask only applies if fmev_shdlctl_thrcreate()
 * is not in use on this handle.
 *
 * fmev_shdlctl_thrsetup() allows you to install a custom door server thread
 * setup function - see door_xcreate(3C).  This will be used with the
 * default thread creation semantics or with any custom thread creation
 * function appointed with fmev_shdlctl_thrcreate().
 *
 * fmev_shdlctl_thrcreate() allows you to install a custom door server thread
 * creation function - see door_xcreate(3C).  This option excludes
 * fmev_shdlctl_{thrattr,sigmask} but the remaining options
 * of fmev_shdlctl_{serialize,thrsetup} are still available.
 */

extern fmev_err_t fmev_shdlctl_serialize(fmev_shdl_t);
extern fmev_err_t fmev_shdlctl_thrattr(fmev_shdl_t, pthread_attr_t *);
extern fmev_err_t fmev_shdlctl_sigmask(fmev_shdl_t, sigset_t *);
extern fmev_err_t fmev_shdlctl_thrsetup(fmev_shdl_t,
    door_xcreate_thrsetup_func_t *, void *);
extern fmev_err_t fmev_shdlctl_thrcreate(fmev_shdl_t,
    door_xcreate_server_func_t *, void *);

/*
 * Specify subscription choices on a handle using fmev_shdl_subscribe as
 * many times as needed to describe the full event set.  The event class
 * pattern can be wildcarded using simple '*' wildcarding.  When an event
 * matching a subscription is received a callback is performed to the
 * nominated function passing a fmev_t handle on the event and the
 * requested cookie argument.
 *
 * See the fault management event protocol specification for a description
 * of event classes.
 *
 * Drop a subscription using fmev_shdl_unsubscribe (which must match an
 * earlier subscription).
 */

#define	FMEV_MAX_CLASS	64	/* Longest class string for subscription */

extern fmev_err_t fmev_shdl_subscribe(fmev_shdl_t, const char *, fmev_cbfunc_t,
    void *);
extern fmev_err_t fmev_shdl_unsubscribe(fmev_shdl_t, const char *);

/*
 * Event access.  In the common case that the event is processed to
 * completion in the context of the event callback you need only
 * use fmev_attr_list to access the nvlist of event attributes,
 * with no responsibility for freeing the event or the nvlist; for
 * convenience, fmev_class and fmev_timestamp can both be used to
 * look inside an event without having to work with the attribute list (and
 * the callback receives the class as an argument).
 *
 * See libnvpair(3LIB) for interfaces to access an nvlist_t.
 *
 * The remaining interfaces apply in the case that event handling will
 * continue beyond the context of the event callback in which it is received.
 *
 * The fmev_t handle received in a callback is reference-counted;
 * the initial reference count on entry to the callback is 1, and the
 * count is always decremented when the callback completes.  To continue
 * to operate on a received event outside of the context of the callback
 * in which it is first received, take an fmev_hold during the callback
 * and later fmev_rele to release your hold (and free the event if the count
 * drops to 0).
 *
 * To access attributes of an event use fmev_attr_list to receive
 * an nvlist_t pointer valid for the same lifetime as the event itself (i.e.,
 * until its reference count drops to zero).
 *
 * If changes are made to a received fmev_t (discouraged) then all who
 * have a hold on the event share the change.  To obtain an independent
 * copy of an fmev_t, with a reference count of 1, use fmev_dup.  When
 * finished with the copy decrement the reference count
 * using fmev_rele - the event will be freed if the count reaches 0.
 *
 * For convenience you can retrieve the class of an event using fmev_class
 * (it's also available as an argument to a callback, and within the
 * event attribute list).  The string returned by fmev_class is valid for
 * the same lifetime as the event itself.
 *
 * The time at which a protocol event was generated is available via
 * fmev_timespec; tv_sec has seconds since the epoch, and tv_nsec nanoseconds
 * past that second.  This can fail with FMEVERR_OVERFLOW if the seconds
 * value does not fit within a time_t;  you can retrieve the 64-bit second
 * and nanosecond values with fmev_time_sec and fmev_time_nsec.
 */

extern nvlist_t *fmev_attr_list(fmev_t);
extern const char *fmev_class(fmev_t);

extern fmev_err_t fmev_timespec(fmev_t, struct timespec *);
extern uint64_t fmev_time_sec(fmev_t);
extern uint64_t fmev_time_nsec(fmev_t);
extern struct tm *fmev_localtime(fmev_t, struct tm *);

extern void fmev_hold(fmev_t);
extern void fmev_rele(fmev_t);
extern fmev_t fmev_dup(fmev_t);

/*
 * The following will allocate and free memory based on the choices made
 * at fmev_shdl_init.
 */
void *fmev_shdl_alloc(fmev_shdl_t, size_t);
void *fmev_shdl_zalloc(fmev_shdl_t, size_t);
void fmev_shdl_free(fmev_shdl_t, void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFMEVENT_H */
