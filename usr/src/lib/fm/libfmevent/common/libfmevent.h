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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LIBFMEVENT_H
#define	_LIBFMEVENT_H

/*
 * FMA event library.
 *
 * A. Protocol event subscription interfaces (Committed).
 * B. Raw event publication interfaces (Consolidation Private).
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
 *
 *				Introduced in
 *	API Function		LIBFMEVENT_VERSION_*
 *	-----------------------	--------------------
 *	fmev_attr_list;		1
 *	fmev_class;		1
 *	fmev_dup;		1
 *	fmev_ev2shdl		2
 *	fmev_hold;		1
 *	fmev_localtime;		1
 *	fmev_rele;		1
 *	fmev_shdl_alloc;	1
 *	fmev_shdl_init;		1
 *	fmev_shdl_fini;		1
 *	fmev_shdl_free;		1
 *	fmev_shdl_getauthority	2
 *	fmev_shdl_nvl2str	2
 *	fmev_shdl_strdup	2
 *	fmev_shdl_strfree	2
 *	fmev_shdl_subscribe;	1
 *	fmev_shdl_unsubscribe;	1
 *	fmev_shdl_zalloc;	1
 *	fmev_shdlctl_serialize;	1
 *	fmev_shdlctl_sigmask;	1
 *	fmev_shdlctl_thrattr;	1
 *	fmev_shdlctl_thrcreate;	1
 *	fmev_shdlctl_thrsetup;	1
 *	fmev_strerror;		1
 *	fmev_timespec;		1
 *	fmev_time_nsec;		1
 *	fmev_time_sec;		1
 */

#define	LIBFMEVENT_VERSION_1	1
#define	LIBFMEVENT_VERSION_2	2

#define	LIBFMEVENT_VERSION_LATEST	LIBFMEVENT_VERSION_2

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
    FMEVERR_INVALIDARG, /* Argument is invalid */
    FMEVERR_STRING2BIG, /* String argument exceeds maximum length */
    FMEVERR_VARARGS_MALFORMED, /* Varargs list bad or incorrectly terminated */
    FMEVERR_VARARGS_TOOLONG, /* Varargs list exceeds maximum length */
    FMEVERR_BADRULESET, /* Ruleset selected for publication is bad */
    FMEVERR_BADPRI, /* Priority selected for publication is bad */
    FMEVERR_TRANSPORT, /* Error in underlying event transport implementation */
    FMEVERR_NVLIST /* nvlist argument is not of type NV_UNIQUE_NAME */
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
 * This is a Committed interface (see attributes(7) for a definition).
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
 * Retrieve an authority nvlist for the fault manager that is forwarding
 * events to us.  This may be NULL if the fault manager has not yet
 * started up and made the information available.  The caller is
 * responsible for freeing the nvlist returned.
 */
extern fmev_err_t fmev_shdl_getauthority(fmev_shdl_t, nvlist_t **);

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
 *
 * An FMRI in an event payload is typically in nvlist form, i.e
 * DATA_TYPE_NVLIST.  That form is useful for extracting individual
 * component fields, but that requires knowledge of the FMRI scheme and
 * Public commitment thereof.  FMRIs are typically Private, but in some
 * cases they can be descriptive such as in listing the ASRU(s) affected
 * by a fault; so we offer an API member which will blindly render any
 * FMRI in its string form.  Use fmev_shdl_nvl2str to format an nvlist_t
 * as a string (if it is recognized as an FMRI); the caller is responsible
 * for freeing the returned string using fmev_shdl_strfree.  If
 * fmev_shdl_nvl2str fails it will return NULL with fmev_errno set -
 * FMEVERR_INVALIDARG if the nvlist_t does not appear to be a valid/known FMRI,
 * FMEVERR_ALLOC if an allocation for memory for the string failed.
 *
 * fmev_ev2shdl will return the fmev_shdl_t with which a received fmev_t
 * is associated.  It should only be used in an event delivery callback
 * context and for the event received in that callback.
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

extern char *fmev_shdl_nvl2str(fmev_shdl_t, nvlist_t *);

extern fmev_shdl_t fmev_ev2shdl(fmev_t);

/*
 * The following will allocate and free memory based on the choices made
 * at fmev_shdl_init.
 */
void *fmev_shdl_alloc(fmev_shdl_t, size_t);
void *fmev_shdl_zalloc(fmev_shdl_t, size_t);
void fmev_shdl_free(fmev_shdl_t, void *, size_t);
extern char *fmev_shdl_strdup(fmev_shdl_t, char *);
extern void fmev_shdl_strfree(fmev_shdl_t, char *);

/*
 * Part B - Raw Event Publication
 * ======
 *
 * The following interfaces are private to the Solaris system and are
 * subject to change at any time without notice.  Applications using
 * these interfaces will fail to run on future releases.  The interfaces
 * should not be used for any purpose until they are publicly documented
 * for use outside of Sun.  These interface are *certain* to change
 * incompatibly, as the current interface is very much purpose-built for
 * a limited application.
 *
 * The interfaces below allow a process to publish a "raw" event
 * which will be transmitted to the fault manager and post-processed
 * into a full FMA protocol event.  The post-processing to be applied
 * is selected by a "ruleset" specified either implicitly or explicitly
 * at publication.  A ruleset will take the raw event (comprising
 * class, subclass, priority, raw payload) and mark it up into a full
 * protocol event; it may also augment the payload through looking up
 * details that would have been costly to compute at publication time.
 *
 * In this first implementation event dispatch is synchronous and blocking,
 * and not guaranteed to be re-entrant.  This limits the call sites
 * at which publication calls can be placed, and also means that careful
 * thought is required before sprinkling event publication code throughout
 * common system libraries.  The dispatch mechanism amounts to some
 * nvlist chicanery followed by a sysevent_evc_publish.  A future revision
 * will relax the context from which one may publish, and add more-powerful
 * publication interfaces.
 *
 * Some publication interfaces (those ending in _nvl) accept a preconstructed
 * nvlist as raw event payload.  We require that such an nvlist be of type
 * NV_UNIQUE_NAME.  The publication interfaces all call nvlist_free on any
 * nvlist that is passed for publication.
 *
 * Other publication interfaces allow you to build up the raw event payload
 * by specifying the members in a varargs list terminated by FMEV_ARG_TERM.
 * Again we require that payload member names are unique (that is, you cannot
 * have two members with the same name but different datatype).  See
 * <sys/nvpair.h> for the data_type_t enumeration of types supported - but
 * note that DATA_TYPE_BOOLEAN is excluded (DATA_TYPE_BOOLEAN_VALUE is
 * supported).  A single-valued (non-array type) member is specified with 3
 * consecutive varargs as:
 *
 *	(char *)name, DATA_TYPE_foo, (type)value
 *
 * An array-valued member is specified with 4 consecutive varargs as:
 *
 *	(char *)name, DATA_TYPE_foo_ARRAY, (int)nelem, (type *)arrayptr
 *
 * The varargs list that specifies the nvlist must begin with an
 * integer that specifies the number of members that follow.  For example:
 *
 * uint32_t mode;
 * char *clientname;
 * uint32_t ins[NARGS];
 *
 * fmev_publish("class", "subclass", FMEV_LOPRI,
 *	3,
 *	"mode", DATA_TYPE_UINT32, mode,
 *	"client", DATA_TYPE_STRING, clientname,
 *	"ins", DATA_TYPE_UINT32_ARRAY, sizeof (ins) / sizeof (ins[0]), ins,
 *	FMEV_ARG_TERM);
 *
 * The following tables summarize the capabilities of the various
 * publication interfaces.
 *
 *					     Detector
 * Interface			Ruleset? File/Line Func
 * ---------------------------- -------- --------- ----
 * fmev_publish_nvl		default	 Yes	   No
 * fmev_publish_nvl (C99)	default  Yes	   Yes
 * fmev_rspublish_nvl		chosen	 Yes	   No
 * fmev_rspublish_nvl (C99)	chosen	 Yes	   Yes
 * fmev_publish			default	 No	   No
 * fmev_publish (C99)		default	 Yes	   Yes
 * fmev_rspublish		chosen	 No	   No
 * fmev_rspublish (C99)		chosen	 Yes	   Yes
 *
 * Summary: if not using C99 then try to use the _nvl variants as the
 * varargs variants will not include file, line or function in the
 * detector.
 */

/*
 * In publishing an event you must select a "ruleset" (or accept the
 * defaults).  Rulesets are listed in the following header.
 */
#include <fm/libfmevent_ruleset.h>

/*
 * In publishing an event we can specify a class and subclass (which
 * in post-processing combine in some way selected by the ruleset to
 * form a full event protocol class).  The maximum class and subclass
 * string lengths are as follows.
 */
#define	FMEV_PUB_MAXCLASSLEN	32
#define	FMEV_PUB_MAXSUBCLASSLEN	32

/*
 * Events are either high-priority (try really hard not to lose) or
 * low-priority (can drop, throttle etc).  Convert a fmev_pri_t to
 * a string with fmev_pri_string().
 */
typedef enum fmev_pri {
	FMEV_LOPRI = 0x1000,
	FMEV_HIPRI
} fmev_pri_t;

extern const char *fmev_pri_string(fmev_pri_t);

/*
 * The varargs event publication interfaces must terminate the list
 * of nvpair specifications with FMEV_ARG_TERM.  This is to guard
 * against very easily-made mistakes in those arg lists.
 */
#define	FMEV_ARG_TERM	(void *)0xa4a3a2a1

/*
 * The following are NOT for direct use.
 */
extern fmev_err_t _i_fmev_publish_nvl(
    const char *, const char *, int64_t,
    const char *, const char *, const char *,
    fmev_pri_t, nvlist_t *);

extern fmev_err_t _i_fmev_publish(
    const char *, const char *, int64_t,
    const char *, const char *, const char *,
    fmev_pri_t,
    uint_t, ...);

/*
 * Post-processing will always generate a "detector" payload member.  In
 * the case of the _nvl publishing variants the detector information
 * includes file and line number, and - if your application is compiled
 * with C99 enabled - function name.
 */
#if __STDC_VERSION__ - 0 >= 199901L
#define	_FMEVFUNC	__func__
#else
#define	_FMEVFUNC	NULL
#endif

/*
 * All these definitions "return" an fmev_err_t.
 *
 * In the _nvl variants you pass a preconstructed event payload; otherwise
 * you include an integer indicating the number of payload
 * (name, type, value) tuples that follow, then all those tuples, finally
 * terminated by FMEV_ARG_TERM.
 *
 * In the rspublish variants you select a ruleset from
 * libfmevent_ruleset.h - just use the final suffix (as in
 * DEFAULT, EREPORT, ISV).
 *
 * The primary classification must not be NULL or the empty string.
 *
 *	arg	type		Description
 *	------- --------------- -------------------------------------------
 *	ruleset	const char *	Ruleset; can be NULL (implies default ruleset)
 *	cl1	const char *	Primary classification string
 *	cl2	const char *	Secondary classification string
 *	pri	fmev_pri_t	Priority
 *	nvl	nvlist_t *	Preconstructed attributes; caller must free
 *	ntuples	int		Number of tuples before FMEV_ARG_TERM
 *	suffix	-		See above.
 */

/*
 * fmev_publish_nvl - Default ruleset implied; class/subclass, pri and an nvl
 */
#define	fmev_publish_nvl(cl1, cl2, pri, nvl) \
	_i_fmev_publish_nvl( \
	    __FILE__, _FMEVFUNC, __LINE__, \
	    FMEV_RULESET_DEFAULT, cl1, cl2, \
	    pri, nvl)

/*
 * fmev_rspublish_nvl - As fmev_publish_nvl, but with a chosen ruleset.
 */
#define	fmev_rspublish_nvl(ruleset, cl1, cl2, pri, nvl) \
	_i_fmev_publish_nvl( \
	    __FILE__, _FMEVFUNC, __LINE__, \
	    ruleset, cl1, cl2, \
	    pri, nvl)

#if __STDC_VERSION__ - 0 >= 199901L && !defined(__lint)

/*
 * fmev_publish (C99 version) - Default ruleset; class/subclass, pri, nvpairs
 */
#define	fmev_publish(cl1, cl2, pri, ntuples, ...) \
	_i_fmev_publish( \
	    __FILE__, __func__, __LINE__, \
	    FMEV_RULESET_DEFAULT, cl1, cl2, \
	    pri, \
	    ntuples, __VA_ARGS__)


/*
 * fmev_rspublish (C99 version) - As fmev_publish, but with a chosen ruleset.
 */
#define	fmev_rspublish(ruleset, cl1, cl2, pri, ntuples, ...) \
	_i_fmev_publish( \
	    __FILE__, __func__, __LINE__, \
	    ruleset, cl1, cl2, \
	    pri, \
	    ntuples, __VA_ARGS__)

#else

/*
 * fmev_publish (pre C99)
 */
extern fmev_err_t fmev_publish(const char *, const char *,
    fmev_pri_t, uint_t, ...);

/*
 * fmev_rspublish (pre C99)
 */
extern fmev_err_t fmev_rspublish(const char *, const char *, const char *,
    fmev_pri_t, uint_t, ...);

#endif /* __STDC_VERSION__ */

#ifdef __cplusplus
}
#endif

#endif /* _LIBFMEVENT_H */
