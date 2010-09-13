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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <libnvpair.h>
#include <libintl.h>
#include "piclenvmond.h"

/* external funcs and varaibles */
extern void env_handle_event(const char *, const void *, size_t);
extern picl_errno_t env_init();
extern void env_platmod_fini();
extern int sensor_fd;
extern pthread_t env_temp_thr_tid;

/* local defines */
#define	TIMEOUT	(10)

#pragma	init(piclenvmond_register)

/*
 * Plugin registration entry points
 */
static void piclenvmond_register(void);
static void piclenvmond_init(void);
static void piclenvmond_fini(void);
static void piclenvmond_evhandler(const char *, const void *, size_t, void *);

int env_debug = 0x0;

static picld_plugin_reg_t envmond_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclenvmond",
	piclenvmond_init,
	piclenvmond_fini
};

typedef struct {
	picl_nodehdl_t nodehdl;
	char node_name[PICL_PROPNAMELEN_MAX];
} env_callback_args_t;

/*
 * picld entry points
 */
static void
piclenvmond_register(void)
{
	(void) picld_plugin_register(&envmond_reg_info);
}

/*
 * picld entry point
 *  - do all the initialization
 *  - register for interested picl events
 */
static void
piclenvmond_init(void)
{
	picl_errno_t rc = PICL_SUCCESS;

	if ((rc = env_init()) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:envmond init failed, "
			"error = %d"), rc);
		return;
	}

	/* register handler for state change events */
	(void) ptree_register_handler(PICLEVENT_STATE_CHANGE,
		piclenvmond_evhandler, NULL);
	/* register handler for condition change events */
	(void) ptree_register_handler(PICLEVENT_CONDITION_CHANGE,
		piclenvmond_evhandler, NULL);

}

static void
piclenvmond_fini(void)
{
	void		*exitval;

	/* unregister event handler */
	(void) ptree_unregister_handler(PICLEVENT_STATE_CHANGE,
		piclenvmond_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_CONDITION_CHANGE,
		piclenvmond_evhandler, NULL);

	/* cancel all the threads */
	(void) pthread_cancel(env_temp_thr_tid);
	(void) pthread_join(env_temp_thr_tid, &exitval);

	/* do any platform specific cleanups required */
	env_platmod_fini();
	(void) close(sensor_fd);
}

/*ARGSUSED*/
static void
piclenvmond_evhandler(const char *ename, const void *earg, size_t size,
	void *cookie)
{
	env_handle_event(ename, earg, size);
}

/*
 * Utility functions
 */

/*
 * create_property -- Create a PICL property
 */
picl_errno_t
env_create_property(int ptype, int pmode, size_t psize, char *pname,
	int (*readfn)(ptree_rarg_t *, void *),
	int (*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t nodeh, picl_prophdl_t *propp, void *vbuf)
{
	picl_errno_t		rc;		/* return code */
	ptree_propinfo_t	propinfo;	/* propinfo structure */
	picl_prophdl_t		proph;

	rc = ptree_get_prop_by_name(nodeh, pname, &proph);
	if (rc == PICL_SUCCESS) {	/* prop. already exists */
		return (rc);
	}

	rc = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		ptype, pmode, psize, pname, readfn, writefn);
	if (rc != PICL_SUCCESS) {
		syslog(LOG_ERR, PTREE_INIT_PROPINFO_FAILED_MSG, rc);
		return (rc);
	}

	rc = ptree_create_and_add_prop(nodeh, &propinfo, vbuf, propp);
	if (rc != PICL_SUCCESS) {
		syslog(LOG_ERR, PTREE_CREATE_AND_ADD_PROP_FAILED_MSG, rc);
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * The picl event completion handler.
 */
/* ARGSUSED */
static void
event_completion_handler(char *ename, void *earg, size_t size)
{
	free(earg);
	free(ename);
}

/*
 * utility routine to post PICL events
 */
/*ARGSUSED*/
static int
post_picl_event(const char *ename, char	*envl, size_t elen,
	picl_nodehdl_t nodeh, int cond_wait)
{
	nvlist_t	*nvlp;
	size_t		nvl_size;
	char		*pack_buf = NULL;
	char		*evname;

	if (nodeh == 0) {
		return (PICL_FAILURE);
	}
	if ((evname = strdup(ename)) == NULL)
		return (PICL_FAILURE);
	if (envl) {
		if (nvlist_unpack(envl, elen, &nvlp, 0) < 0) {
			nvlist_free(nvlp);
			free(evname);
			return (PICL_FAILURE);
		}
	} else {
		if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, NULL)) {
			free(evname);
			return (PICL_FAILURE);
		}
	}

	if (nvlist_add_uint64(nvlp, PICLEVENTARG_NODEHANDLE, nodeh) == -1) {
		nvlist_free(nvlp);
		free(evname);
		return (PICL_FAILURE);
	}

	if (nvlist_pack(nvlp, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		nvlist_free(nvlp);
		free(evname);
		return (PICL_FAILURE);
	}
	nvlist_free(nvlp);

	if (env_debug & EVENTS) {
		char enodename[PICL_PROPNAMELEN_MAX];
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_NAME,
			enodename, sizeof (enodename)) == PICL_SUCCESS)
			syslog(LOG_INFO, "envmond:Posting %s on %s\n",
				ename, enodename);
	}

	if (ptree_post_event(evname, pack_buf, nvl_size,
		event_completion_handler) != 0) {
		syslog(LOG_ERR, gettext("SUNW_envmond: Error posting %s PICL"
			" event."), ename);
		free(pack_buf);
		free(evname);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * post dr_req events
 */
picl_errno_t
post_dr_req_event(picl_nodehdl_t fruh, char *dr_req_type, uint8_t wait)
{
	nvlist_t	*nvlp;	/* nvlist of event specific args */
	size_t		nvl_size;
	char		*pack_buf = NULL;
	char		dr_ap_id[PICL_PROPNAMELEN_MAX];
	int rc = PICL_SUCCESS;

	if (env_debug & DEBUG)
		syslog(LOG_DEBUG, "Post %s on %llx", dr_req_type, fruh);
	if (fruh == 0) {
		return (PICL_INVALIDARG);
	}
	if ((rc = ptree_get_propval_by_name(fruh, PICL_PROP_NAME,
		dr_ap_id, sizeof (dr_ap_id))) != PICL_SUCCESS) {
		return (rc);
	}

	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, NULL)) {
		return (PICL_FAILURE);
	}

	if (nvlist_add_string(nvlp, PICLEVENTARG_AP_ID, dr_ap_id) == -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	if (nvlist_add_string(nvlp, PICLEVENTARG_DR_REQ_TYPE, dr_req_type)
		== -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	if (nvlist_pack(nvlp, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	nvlist_free(nvlp);

	if (env_debug & DEBUG)
		syslog(LOG_DEBUG, "Posting %s on %s", dr_req_type, dr_ap_id);
	rc = post_picl_event(PICLEVENT_DR_REQ, pack_buf, nvl_size, fruh,
		wait);

	free(pack_buf);
	return (rc);
}

/*
 * routine to post dr_ap_state change events
 */
picl_errno_t
post_dr_ap_state_change_event(picl_nodehdl_t nodehdl, char *dr_hint,
	uint8_t wait)
{
	nvlist_t	*nvlp;	/* nvlist of event specific args */
	size_t		nvl_size;
	char		*pack_buf = NULL;
	char		dr_ap_id[PICL_PROPNAMELEN_MAX];
	int rc = PICL_SUCCESS;

	if (nodehdl == 0) {
		return (PICL_FAILURE);
	}
	if ((rc = ptree_get_propval_by_name(nodehdl, PICL_PROP_NAME,
		dr_ap_id, sizeof (dr_ap_id))) != PICL_SUCCESS) {
		return (rc);
	}
	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, NULL)) {
		return (PICL_FAILURE);
	}

	if (nvlist_add_string(nvlp, PICLEVENTARG_AP_ID, dr_ap_id) == -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	if (nvlist_add_string(nvlp, PICLEVENTARG_HINT, dr_hint) == -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	if (nvlist_pack(nvlp, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	nvlist_free(nvlp);
	rc = post_picl_event(PICLEVENT_DR_AP_STATE_CHANGE, pack_buf,
		nvl_size, nodehdl, wait);
	free(pack_buf);
	return (rc);
}

picl_errno_t
post_cpu_state_change_event(picl_nodehdl_t fruh, char *event_type, uint8_t wait)
{
	nvlist_t	*nvlp;	/* nvlist of event specific args */
	size_t		nvl_size;
	char		*pack_buf = NULL;
	int rc = PICL_SUCCESS;

	if (fruh == 0) {
		return (PICL_FAILURE);
	}

	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, NULL))
		return (PICL_FAILURE);

	if (nvlist_add_int64(nvlp, PICLEVENTARG_NODEHANDLE, fruh)) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}

	if (nvlist_add_string(nvlp, PICLEVENTARG_CPU_EV_TYPE,
		event_type) == -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}

	if (nvlist_pack(nvlp, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	nvlist_free(nvlp);
	rc = post_picl_event(PICLEVENT_CPU_STATE_CHANGE, pack_buf,
		nvl_size, fruh, wait);
	free(pack_buf);
	return (rc);
}

int
post_sensor_event(picl_nodehdl_t hdl, char *sensor_evalue, uint8_t wait)
{
	nvlist_t	*nvlp;	/* nvlist of event specific args */
	size_t		nvl_size;
	char		*pack_buf = NULL;
	char		dr_ap_id[PICL_PROPNAMELEN_MAX];
	int rc = PICL_SUCCESS;

	if (env_debug & DEBUG)
		syslog(LOG_DEBUG, "Post %s on %llx", sensor_evalue, hdl);
	if (hdl == 0)
		return (PICL_FAILURE);

	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME_TYPE, NULL))
		return (PICL_FAILURE);

	if (nvlist_add_string(nvlp, PICLEVENTARG_CONDITION,
		sensor_evalue) == -1) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	if (nvlist_pack(nvlp, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		nvlist_free(nvlp);
		return (PICL_FAILURE);
	}
	nvlist_free(nvlp);

	if (env_debug & DEBUG) {
		if (ptree_get_propval_by_name(hdl, PICL_PROP_NAME, dr_ap_id,
			sizeof (dr_ap_id)) == PICL_SUCCESS)
			syslog(LOG_DEBUG, "Posting %s on %s", sensor_evalue,
				dr_ap_id);
	}
	rc = post_picl_event(PICLEVENT_CONDITION_CHANGE, pack_buf, nvl_size,
		hdl, wait);
	free(pack_buf);
	return (rc);
}

/*
 * return B_TRUE if admin lock is enabled
 * return B_FALSE if admin lock is disabled
 */
boolean_t
env_admin_lock_enabled(picl_nodehdl_t fruh)
{
	char		adminlock[PICL_PROPNAMELEN_MAX];

	if (ptree_get_propval_by_name(fruh, PICL_PROP_ADMIN_LOCK,
		adminlock, sizeof (adminlock))
		!= PICL_SUCCESS) {
		return (B_FALSE);
	}
	if (strcmp(adminlock, PICL_ADMINLOCK_ENABLED) == 0) {
		return (B_TRUE);
	}
	return (B_FALSE);
}
