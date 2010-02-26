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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _OBJECTS_H
#define	_OBJECTS_H

#include <door.h>
#include <libsysevent.h>
#include <libuutil.h>
#include <pthread.h>

#include <libnwam.h>
#include "events.h"
#include "ncp.h"
#include "ncu.h"

/*
 * Wrapper structure for libnwam object,  containing name, type,
 * associated object handle and optional object data field, and uu_list_node.
 */
struct nwamd_object {
	char nwamd_object_name[NWAM_MAX_NAME_LEN];
	nwam_object_type_t nwamd_object_type;

	/*
	 * These two elements provide a reference count for the structure and
	 * a lock for the data including reference count.
	 */
	int nwamd_object_refcount;
	pthread_mutex_t nwamd_object_mutex;

	void *nwamd_object_handle; /* can point at ENMs, locations, etc. */
	nwamd_ncu_t *nwamd_object_data;
	nwam_state_t nwamd_object_state;
	nwam_aux_state_t nwamd_object_aux_state;
	uu_list_node_t nwamd_object_node;
};

/* Object init/enqueueing */
extern void nwamd_object_lists_init(void);
extern void nwamd_object_lists_fini(void);
extern nwamd_object_t nwamd_object_init(nwam_object_type_t, const char *,
    void *, void *);
extern nwamd_object_t nwamd_object_find(nwam_object_type_t, const char *);
extern void nwamd_object_release_and_preserve(nwamd_object_t);
extern void nwamd_object_release(nwamd_object_t);
extern void nwamd_object_release_and_destroy(nwamd_object_t);
extern void nwamd_object_release_after_preserve(nwamd_object_t);
extern void nwamd_object_release_and_destroy_after_preserve(nwamd_object_t);
extern void nwamd_object_set_state(nwam_object_type_t, const char *,
    nwam_state_t, nwam_aux_state_t);
extern void nwamd_object_set_state_timed(nwam_object_type_t, const char *,
    nwam_state_t, nwam_aux_state_t, uint32_t);
extern nwamd_event_method_t *nwamd_object_event_methods(nwam_object_type_t);
extern int nwamd_walk_objects(nwam_object_type_t,
    int (*)(nwamd_object_t, void *), void *);
extern int nwamd_object_update(const char *, nwam_object_type_t);

/* Known WLAN functions (no wlan objects, so no init/fini functions) */
/* event methods */
extern void nwamd_known_wlan_handle_init_event(nwamd_event_t);

/* refresh/destroy a known WLAN */
extern int nwamd_known_wlan_action(const char *, nwam_action_t);

/* ENM functions */
/* Init/fini functions for ENMs */
extern void nwamd_init_enms(void);
extern void nwamd_fini_enms(void);

/* ENM condition check function */
extern void nwamd_enm_check_conditions(void);

/* event methods */
extern void nwamd_enm_handle_init_event(nwamd_event_t);
extern void nwamd_enm_handle_fini_event(nwamd_event_t);

/* enable/disable an enm */
extern int nwamd_enm_action(const char *, nwam_action_t);

/* reread an enm from the repository */
extern int nwamd_enm_refresh(const char *);

/* loc functions */
/* Init/fini functions for locs */
extern void nwamd_init_locs(void);
extern void nwamd_fini_locs(void);

/* loc condition check function */
extern void nwamd_loc_check_conditions(void);

/* on shutdown, revert to legacy location */
extern void nwamd_loc_revert_to_legacy(void);

/* event methods */
extern void nwamd_loc_handle_init_event(nwamd_event_t);
extern void nwamd_loc_handle_fini_event(nwamd_event_t);

/* enable/disable a loc */
extern int nwamd_loc_action(const char *, nwam_action_t);

/* reread a loc from the repository */
extern int nwamd_loc_refresh(const char *);

/* NCU functions */
extern void nwamd_init_ncus(void);
extern void nwamd_fini_ncus(void);

/* enable an ncp/ncu */
extern int nwamd_ncp_action(const char *, nwam_action_t);
extern int nwamd_ncu_action(const char *, const char *, nwam_action_t);

/*
 * Event callbacks.
 */
extern void nwamd_ncu_handle_init_event(nwamd_event_t);
extern void nwamd_ncu_handle_fini_event(nwamd_event_t);
extern void nwamd_ncu_handle_if_state_event(nwamd_event_t);
extern void nwamd_ncu_handle_if_action_event(nwamd_event_t);
extern void nwamd_ncu_handle_link_state_event(nwamd_event_t);
extern void nwamd_ncu_handle_link_action_event(nwamd_event_t);
extern void nwamd_ncu_handle_init_event(nwamd_event_t);
extern void nwamd_ncu_handle_fini_event(nwamd_event_t);
extern void nwamd_ncu_handle_action_event(nwamd_event_t);
extern void nwamd_ncu_handle_state_event(nwamd_event_t);

extern void nwamd_ncp_handle_action_event(nwamd_event_t);
extern void nwamd_ncp_handle_state_event(nwamd_event_t);
extern void nwamd_ncu_handle_periodic_scan_event(nwamd_event_t);
extern void nwamd_ncp_handle_enable_event(nwamd_event_t);
extern void nwamd_handle_upgrade(nwamd_event_t);

extern void nwamd_enm_handle_action_event(nwamd_event_t);
extern void nwamd_enm_handle_state_event(nwamd_event_t);

extern void nwamd_loc_handle_action_event(nwamd_event_t);
extern void nwamd_loc_handle_state_event(nwamd_event_t);

extern void nwamd_known_wlan_handle_action_event(nwamd_event_t);

extern void nwamd_add_phys_ncu_auto(nwam_ncp_handle_t, const char *);
extern void nwamd_rem_phys_ncu_auto(nwam_ncp_handle_t, const char *);
extern void add_auto_link(nwam_ncp_handle_t, const char *);
extern void add_auto_ip(nwam_ncp_handle_t, const char *);
extern void rem_auto_link(nwam_ncp_handle_t, const char *);
extern void rem_auto_ip(nwam_ncp_handle_t, const char *);

#endif /* _OBJECTS_H */
