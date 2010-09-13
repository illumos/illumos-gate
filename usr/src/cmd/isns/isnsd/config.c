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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <libscf.h>
#include <pthread.h>

#include "isns_server.h"
#include "isns_log.h"
#include "isns_cfg.h"

/*
 * external variables
 */
extern uint64_t esi_threshold;
extern uint8_t mgmt_scn;
extern ctrl_node_t *control_nodes;
extern pthread_mutex_t ctrl_node_mtx;
extern char data_store[MAXPATHLEN];

#define	DEFAULT_ESI_THRESHOLD	3
#define	MAX_ESI_THRESHOLD	10

/*
 * load_config loads config data through SMF.
 * arg DATA_STORE_UPDATE indicates whether the data store location
 * can be updated or not.
 */
int
load_config(boolean_t DATA_STORE_UPDATE)
{

	int retval = -1;

	scf_handle_t	*handle = NULL;
	scf_scope_t	*sc = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*value = NULL;
	scf_iter_t	*value_iter = NULL;

	ctrl_node_t *ctrl_node_p;
	char scf_name[MAXNAMELEN];
	char *name;

	/* connect to the current SMF global repository */
	handle = scf_handle_create(SCF_VERSION);

	/* allocate scf resources */
	sc = scf_scope_create(handle);
	svc = scf_service_create(handle);
	pg = scf_pg_create(handle);
	prop = scf_property_create(handle);
	value = scf_value_create(handle);
	value_iter = scf_iter_create(handle);

	/* if failed to allocate resources, exit */
	if (handle == NULL || sc == NULL || svc == NULL || pg == NULL ||
	    prop == NULL || value == NULL || value_iter == NULL) {
		isnslog(LOG_DEBUG, "load_config",
		    "scf handles allocation failed.");
		goto out;
	}

	/* bind scf handle to the running svc.configd daemon */
	if (scf_handle_bind(handle) == -1) {
		isnslog(LOG_DEBUG, "load_config", "scf binding failed.");
		goto out;
	}

	/* get the scope of the localhost in the current repository */
	if (scf_handle_get_scope(handle, SCF_SCOPE_LOCAL, sc) == -1) {
		isnslog(LOG_DEBUG, "load_config", "Getting scf scope failed.");
		goto out;
	}

	/* get the service "network/isns_server" within the scope */
	if (scf_scope_get_service(sc, ISNS_SERVER_SVC_NAME, svc) == -1) {
		isnslog(LOG_DEBUG, "load_config", "Getting %s service failed.",
		    ISNS_SERVER_SVC_NAME);
		goto out;
	}

	/* get the property group "config" within the given service */
	if (scf_service_get_pg(svc, ISNS_SERVER_CONFIG, pg) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property group %s failed.",
		    ISNS_SERVER_CONFIG);
		goto out;
	}

	/*
	 * Now get the properties.
	 */
	if (scf_pg_get_property(pg, CONFIG_ESI_THRESHOLD, prop) == -1) {
		isnslog(LOG_DEBUG, "load_config", "Getting property %s failed",
		    CONFIG_ESI_THRESHOLD);
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property value for %s failed.",
		    CONFIG_ESI_THRESHOLD);
		goto out;
	}

	if (scf_value_get_count(value, &esi_threshold) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property integer value for %s failed.",
		    CONFIG_ESI_THRESHOLD);
			goto out;
	}

	/* the range of ESI Threshold is [1, 10] */
	if (esi_threshold < 1) {
		esi_threshold = DEFAULT_ESI_THRESHOLD; /* 3 */
	} else if (esi_threshold > MAX_ESI_THRESHOLD) {
		esi_threshold = MAX_ESI_THRESHOLD; /* 10 */
	}

	isnslog(LOG_DEBUG, "load_config",
	    "%s set to %d", CONFIG_ESI_THRESHOLD, esi_threshold);

	if (scf_pg_get_property(pg, CONFIG_MGMT_SCN, prop) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting scf property %s failed.", CONFIG_MGMT_SCN);
			goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property value for %s failed.",
		    CONFIG_MGMT_SCN);
		goto out;
	}

	if (scf_value_get_boolean(value, &mgmt_scn) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting boolean value for property %s failed",
		    CONFIG_MGMT_SCN);
		goto out;
	}
	isnslog(LOG_DEBUG, "load_config",
	    "%s set to %s", CONFIG_MGMT_SCN,
	    mgmt_scn ? "true" : "false");

	if (DATA_STORE_UPDATE) {
	    if (scf_pg_get_property(pg, CONFIG_DATA_STORE, prop) == -1) {
		isnslog(LOG_DEBUG, "load_config", "Getting property %s failed",
		    CONFIG_DATA_STORE);
		goto out;
	    }

	    if (scf_property_get_value(prop, value) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property value for %s failed",
		    CONFIG_DATA_STORE);
		goto out;
	    }

	    data_store[0] = 0;
	    if (scf_value_get_astring(value, data_store, MAXPATHLEN) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting property string value for %s failed",
		    CONFIG_DATA_STORE);
		goto out;
	    }
	    isnslog(LOG_DEBUG, "load_config",
		"%s set to %s", CONFIG_DATA_STORE, data_store);
	}

	if (scf_pg_get_property(pg, CONFIG_CONTROL_NODES, prop) == -1) {
		isnslog(LOG_DEBUG, "load_config", "Getting property %s failed",
		    CONFIG_CONTROL_NODES);
		goto out;
	}

	if (scf_iter_property_values(value_iter, prop) == -1) {
		isnslog(LOG_DEBUG, "load_config",
		    "Getting iteration property %s failed",
		    CONFIG_CONTROL_NODES);
		goto out;
	}

	/* remove any old control node first. */
	(void) pthread_mutex_lock(&ctrl_node_mtx);
	while (control_nodes != NULL) {
	    ctrl_node_p = control_nodes->next;
	    free(control_nodes->name);
	    free(control_nodes);
	    control_nodes = ctrl_node_p;
	}

	while (scf_iter_next_value(value_iter, value) != 0) {
		if (scf_value_get_ustring(value, scf_name, MAXNAMELEN) == -1) {
			isnslog(LOG_DEBUG, "load_config",
			    "Getting property string value for %s failed",
			    CONFIG_CONTROL_NODES);
			(void) pthread_mutex_unlock(&ctrl_node_mtx);
			goto out;
		}
		ctrl_node_p = (ctrl_node_t *)malloc(sizeof (ctrl_node_t));
		if (ctrl_node_p == NULL) {
		    isnslog(LOG_DEBUG, "load_config", "malloc() failed.");
		    (void) pthread_mutex_unlock(&ctrl_node_mtx);
		    goto out;
		}
		if (strlen(scf_name) != 0) {
		    name = (char *)malloc(strlen(scf_name) + 1);
		    if (name == NULL) {
			free(ctrl_node_p);
			isnslog(LOG_DEBUG, "load_config", "malloc() failed.");
			(void) pthread_mutex_unlock(&ctrl_node_mtx);
			goto out;
		    } else {
			(void) strcpy(name, scf_name);
			ctrl_node_p->name = (uchar_t *)name;
			ctrl_node_p->next = control_nodes;
			control_nodes = ctrl_node_p;
		    }
		    isnslog(LOG_DEBUG, "load_config",
			"%s set to %s", CONFIG_CONTROL_NODES, scf_name);
		} else {
		    free(ctrl_node_p);
		}
	}
	(void) pthread_mutex_unlock(&ctrl_node_mtx);

	isnslog(LOG_DEBUG, "load_config", "loading server settings ok.");

	retval = 0; /* ok */

out:
	/* destroy scf pointers */
	if (value != NULL) {
		scf_value_destroy(value);
	}
	if (value_iter != NULL) {
		scf_iter_destroy(value_iter);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (sc != NULL) {
		scf_scope_destroy(sc);
	}
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}

	return (retval);
}

/*
 * is_control_node checks the given name to see if it is a control node.
 */
int
is_control_node(
	uchar_t *name
)
{
	ctrl_node_t *p;

	(void) pthread_mutex_lock(&ctrl_node_mtx);
	p = control_nodes;
	while (p != NULL) {
		if (strcmp((char *)p->name, (char *)name) == 0) {
		    (void) pthread_mutex_unlock(&ctrl_node_mtx);
		    return (1);
		}
		p = p->next;
	}
	(void) pthread_mutex_unlock(&ctrl_node_mtx);

	return (0);
}
