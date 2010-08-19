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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SW_H
#define	_SW_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <libnvpair.h>
#include <pthread.h>
#include <libuutil.h>

/*
 * We have two real fmd modules - software-diagnosis and software-response.
 * Each hosts a number of subsidiary diagnosis engines and response agents,
 * although these are not fmd modules as such (the intention is to avoid
 * a proliferation of small C diagnosis and response modules).
 *
 * Subsidiary "modules" are not loaded as normal fmd modules are.  Instead
 * each of the real modules software-diagnosis and software-response includes
 * an array listing the subsidiaries it hosts, and when the real module
 * is loaded by fmd it iterates over this list to "load" subsidiaries by
 * calling their nominated init function.
 */

/* Maximum number of subsidiary "modules" */
#define	SW_SUB_MAX	10

/* Maximum number of supported timers across all subsidiaries */
#define	SW_TIMER_MAX	20

/*
 * A subsidiary must perform fmd_hdl_subscribe calls for all events of
 * interest to it.  These are typically performed during its init
 * function.  All subscription callbacks funnel through the shared
 * fmdo_recv entry point; that function walks through the dispatch list
 * for each subsidiary and performs a callback for the first matching entry of
 * each subsidiary.  The init entry point for each subsidiary
 * returns a pointer to an array of struct sw_disp applicable for that
 * entity.
 *
 * Note that the framework does *not* perform any fmd_hdl_subscribe calls
 * on behalf of the subsidiary - the swd_classpat member below is used
 * in routing events, not in establishing subscriptions for them.  A
 * subsidiary can subscribe to say "ireport.foo.a" and "ireport.foo.b"
 * but could elect to nominate a common handler for those via a single
 * struct sw_disp with swd_classpat of "ireport.foo.*".
 */
typedef void sw_dispfunc_t(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, void *);

struct sw_disp {
	const char *swd_classpat;	/* event classes to callback for */
	sw_dispfunc_t *swd_func;	/* callback function */
	void *swd_arg;			/* opaque argument to callback */
};

/*
 * A diagnosis or response subsidiary must provide a struct sw_subinfo with
 * all its pertinent information;  a pointer to this structure must be
 * included in the array of struct sw_subinfo pointers in each of
 * software-diagnosis and software-response.
 *
 * swsub_name
 *	This should be chosen to be unique to this subsidiary;
 *	by convention it should also be the name prefix used in any fmd
 *	buffers	the subsidiary creates.
 *
 * swsub_casetype
 *	A diagnosis subsidiary solves cases using swde_case_* below, and it
 *	must specify in swsub_casetype the type of case it solves.  A response
 *	subsidiary must specify SW_CASE_NONE here.  A subsidiary may only solve
 *	at most one type of case, and no two subsidiaries must solve the same
 *	case type.  We use the case type to associate a subsidiary owner of
 *	the fmd case that is really owned by the host module.
 *
 * swsub_init
 *	The initialization function for this subsidiary, akin to the
 *	_fmd_init in a traditional fmd module.  This must not be NULL.
 *
 *	 When the host diagnosis/response module initializes the _fmd_init
 *	 entry point will call the swsub_init function for each subsidiary
 *	 in turn.  The fmd handle has already been registered and timers are
 *	 available for installation (see below);  the swsub_init function must
 *	 return a pointer to a NULL-terminated array of struct sw_disp
 *	 describing the event dispatch preferences for that module, and fill
 *	 an integer we pass with the number of entries in that array (including
 *	 the terminating NULL entry).  The swsub_init function also receives
 *	 a subsidiary-unique id_t assigned by the framework that it should
 *	 keep a note of for use in timer installation (see below);  this id
 *	 should not be persisted to checkpoint data.
 *
 * swsub_fini
 *	When the host module _fmd_fini is called it will call this function
 *	for each subsidiary.  A subsidiary can specify NULL here.
 *
 * swsub_timeout
 *	This is the timeout function to call for expired timers installed by
 *	this subsidiary.  See sw_timer_{install,remove} below.  May be
 *	NULL if no timers are used by this subsidiary.
 *
 * swsub_case_close
 *	This function is called when a case "owned" by a subsidiary
 *	is the subject of an fmdo_close callback.  Can be NULL, and
 *	must be NULL for a subsidiary with case type SW_CASE_NONE (such
 *	as a response subsidiary).
 *
 * swsub_case_verify
 *	This is called during _fmd_init of the host module.  The host module
 *	iterates over all cases that it owns and calls the verify function
 *	for the real owner which may choose to close cases if they no longer
 *	apply.  Can be NULL, and must be NULL for a subsidiary with case
 *	type SW_CASE_NONE.
 */

/*
 * sw_casetype values are persisted to checkpoints - do not change values.
 */
enum sw_casetype {
	SW_CASE_NONE = 0x0ca5e000,
	SW_CASE_SMF,
	SW_CASE_PANIC
};

/*
 * Returns for swsub_init.  The swsub_fini entry point will only be
 * called for subsidiaries that returned SW_SUB_INIT_SUCCESS on init.
 */
#define	SW_SUB_INIT_SUCCESS		0
#define	SW_SUB_INIT_FAIL_VOLUNTARY	1	/* chose not to init */
#define	SW_SUB_INIT_FAIL_ERROR		2	/* error prevented init */

typedef void swsub_case_close_func_t(fmd_hdl_t *, fmd_case_t *);
typedef int sw_case_vrfy_func_t(fmd_hdl_t *, fmd_case_t *);

struct sw_subinfo {
	const char *swsub_name;
	enum sw_casetype swsub_casetype;
	int (*swsub_init)(fmd_hdl_t *, id_t, const struct sw_disp **, int *);
	void (*swsub_fini)(fmd_hdl_t *);
	void (*swsub_timeout)(fmd_hdl_t *, id_t, void *);
	swsub_case_close_func_t *swsub_case_close;
	sw_case_vrfy_func_t *swsub_case_verify;
};

/*
 * List sw_subinfo for each subsidiary diagnosis and response "module" here
 */
extern const struct sw_subinfo smf_diag_info;
extern const struct sw_subinfo smf_response_info;
extern const struct sw_subinfo panic_diag_info;

/*
 * Timers - as per the fmd module API but with an additional id_t argument
 * specifying the unique id of the subsidiary installing the timer (provided
 * to the subsidiary in its swsub_init call).
 */
extern id_t sw_timer_install(fmd_hdl_t *, id_t, void *, fmd_event_t *,
    hrtime_t);
extern void sw_timer_remove(fmd_hdl_t *, id_t, id_t);

/*
 * The software-diagnosis subsidiaries can open and solve cases; to do so
 * they must use the following wrappers to the usual fmd module API case
 * management functions.  We need this so that a subsidiary can iterate
 * over *its* cases (fmd_case_next would iterate over those of other
 * subsidiaries), receive in the subsidiary a callback when a case it opened
 * is closed, etc.  The subsidiary can use other fmd module API members
 * for case management, such as fmd_case_add_ereport.
 *
 * Each subsidiary opens cases of its own unique type, identified by
 * the sw_casetype enumeration.  The values used in this enumeration
 * must never change - they are written to checkpoint state.
 *
 * swde_case_open
 *	Opens a new case of the correct subsidiary type for the given
 *	subsidiary id.  If a uuid string is provided then open a case
 *	with that uuid using fmd_case_open_uuid, allowing case uuid
 *	to match some relevant uuid that was received in one of the
 *	events that has led us to open this case.
 *
 *	If the subsidiarywishes to associate some persistent
 *	case data with the new case thenit can fmd_hdl_alloc and complete a
 *	suitably-packed serialization structure and include a pointer to it
 *	in the call to sw_case_open together with the structure size and
 *	structure version.  The	framework will create a new fmd buffer (named
 *	for you, based on the case type) and write the structure out to disk;
 *	when the module or fmd is restarted this structure is restored from
 *	disk for you and reassociated with the case - use swde_case_data to
 *	retrieve a pointer to it.
 *
 * swde_case_first, swde_case_next
 *	A subsidiary DE can iterate over its cases using swde_case_first and
 *	swde_case_next.  For swde_case_first quote the subsidiary id;
 *	for swde_case_next quote the last case returned.
 *
 * swde_case_data
 *	Returns a pointer to the previously-serialized case data, and fills
 *	a uint32_t with the version of that serialized data.
 *
 * swde_case_data_write
 *	Whenever a subsidiary modifies its persistent data structure
 *	it must call swde_case_data_write to indicate that the associated
 *	fmd buffer is dirty and needs to be rewritten.
 *
 * swde_case_data_upgrade
 *	If the subsidiary ever revs its persistent structure it needs to call
 *	swde_case_data_upgrade to register the new version and structure size,
 *	and write the structure out to a reallocated fmd buffer;  the old
 *	case data structure (if any) will be freed.  A subsidiary may use
 *	this interface to migrate old persistence structures restored from
 *	checkpoint - swde_case_data will return a version number below the
 *	current.
 */

extern fmd_case_t *swde_case_open(fmd_hdl_t *, id_t, char *, uint32_t,
    void *, size_t);
extern fmd_case_t *swde_case_first(fmd_hdl_t *, id_t);
extern fmd_case_t *swde_case_next(fmd_hdl_t *, fmd_case_t *);
extern void *swde_case_data(fmd_hdl_t *, fmd_case_t *, uint32_t *);
extern void swde_case_data_write(fmd_hdl_t *, fmd_case_t *);
extern void swde_case_data_upgrade(fmd_hdl_t *, fmd_case_t *, uint32_t,
    void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SW_H */
