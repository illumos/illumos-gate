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

#include <arpa/inet.h>
#include <errno.h>
#include <inet/ip.h>
#include <inetcfg.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlwlan.h>
#include <libscf.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libnwam.h>
#include "conditions.h"
#include "events.h"
#include "objects.h"
#include "util.h"

/*
 * enm.c - contains routines which handle ENM (external network modifier)
 * abstraction.  ENMs represent scripts or services that can be activated either
 * manually or in response to network conditions.
 */

#define	CTRUN	"/usr/bin/ctrun"

static int
enm_create_init_fini_event(nwam_enm_handle_t enmh, void *data)
{
	boolean_t *init = data;
	char *name;
	nwamd_event_t enm_event;

	if (nwam_enm_get_name(enmh, &name) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "enm_init_fini: could not get ENM name");
		return (0);
	}

	enm_event = nwamd_event_init(*init ?
	    NWAM_EVENT_TYPE_OBJECT_INIT : NWAM_EVENT_TYPE_OBJECT_FINI,
	    NWAM_OBJECT_TYPE_ENM, 0, name);
	if (enm_event != NULL)
		nwamd_event_enqueue(enm_event);
	free(name);

	return (0);
}

/*
 * Walk all ENMs, creating init events for each.
 */
void
nwamd_init_enms(void)
{
	boolean_t init = B_TRUE;

	(void) nwam_walk_enms(enm_create_init_fini_event, &init, 0, NULL);
}

/*
 * Walk all ENMs, creating fini events for each.
 */
void
nwamd_fini_enms(void)
{
	boolean_t init = B_FALSE;

	(void) nwam_walk_enms(enm_create_init_fini_event, &init, 0, NULL);
}

static boolean_t
enm_is_enabled(nwam_enm_handle_t enmh)
{
	nwam_value_t enabledval;
	boolean_t enabled = B_FALSE;

	if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ENABLED,
	    &enabledval) != NWAM_SUCCESS) {
		/* It's legal for a conditional ENM to not specify "enabled" */
		return (B_FALSE);
	}
	if (nwam_value_get_boolean(enabledval, &enabled) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "enm_is_enabled: could not retrieve "
		    "enabled value");
	}
	nwam_value_free(enabledval);
	return (enabled);
}

static int64_t
enm_get_activation_mode(nwam_enm_handle_t enmh)
{
	uint64_t activation;
	int64_t ret;
	nwam_value_t activationval;

	if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ACTIVATION_MODE,
	    &activationval)  != NWAM_SUCCESS) {
		nlog(LOG_ERR, "enm_get_activation_mode: could not retrieve "
		    "activation mode value");
		return (-1);
	}
	if (nwam_value_get_uint64(activationval, &activation) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "enm_get_activation_mode: could not retrieve "
		    "activation mode value");
		ret = -1;
	} else {
		ret = activation;
	}
	nwam_value_free(activationval);

	return (ret);
}

static void *
nwamd_enm_activate_deactivate_thread(void *arg)
{
	char *object_name = arg;
	nwamd_object_t object;
	nwam_enm_handle_t enmh;
	nwam_value_t scriptval = NULL;
	nwam_state_t state;
	nwam_aux_state_t aux_state;
	char *script, *copy = NULL;
	const char **argv = NULL;
	boolean_t going_online, disable_succeeded = B_FALSE;
	int ret;

	object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM, object_name);
	if (object == NULL) {
		nlog(LOG_ERR, "nwamd_enm_activate_deactivate_thread: "
		    "could not find ENM %s", object_name);
		goto done;
	}
	enmh = object->nwamd_object_handle;

	going_online =
	    (object->nwamd_object_state == NWAM_STATE_OFFLINE_TO_ONLINE);
	/*
	 * We're starting if current state is offline* and stopping otherwise.
	 */
	if (nwam_enm_get_prop_value(enmh,
	    going_online ? NWAM_ENM_PROP_START : NWAM_ENM_PROP_STOP,
	    &scriptval) != NWAM_SUCCESS ||
	    nwam_value_get_string(scriptval, &script) != NWAM_SUCCESS) {
		/*
		 * If we're stopping, it's not an error for no script to
		 * be specified.
		 */
		nlog(going_online ? LOG_ERR : LOG_DEBUG,
		    "nwamd_enm_activate_deactivate_thread: "
		    "no script specified for enm %s", object_name);
		if (going_online) {
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_METHOD_MISSING;
		} else {
			disable_succeeded = B_TRUE;
		}
	} else {
		char *lasts;
		const char **newargv;
		int i = 0;
		struct timeval now;

		nlog(LOG_DEBUG, "nwamd_enm_activate_deactivate_thread: "
		    "running script %s for ENM %s", script, object_name);

		/*
		 * The script may take a number of arguments. We need to
		 * create a string array consisting of the wrapper command
		 * (ctrun), ENM script name, arguments and NULL array
		 * terminator.  Start with an array of size equal to the
		 * string length (since the number of arguments will always
		 * be less than this) and shrink array to the actual number
		 * of arguments when we have parsed the string.
		 */
		if ((copy = strdup(script)) == NULL ||
		    (argv = calloc(strlen(script), sizeof (char *))) == NULL) {
			ret = 1;
			goto err;
		}
		argv[i++] = CTRUN;
		argv[i++] = strtok_r(copy, " ", &lasts);
		if (argv[1] == NULL) {
			ret = 1;
			goto err;
		}

		for (; (argv[i] = strtok_r(NULL, " ", &lasts)) != NULL; i++) {}

		newargv = realloc(argv, (i + 1) * sizeof (char *));
		argv = newargv;

		/* Store the current time as the time the script began */
		(void) gettimeofday(&now, NULL);
		object->nwamd_script_time = now;

		/*
		 * Release the object so that it is not blocked while the
		 * script is running.
		 */
		nwamd_object_release(object);

		ret = nwamd_start_childv(CTRUN, argv);

		/*
		 * Find the object again, now that the script has finished
		 * running.  Check if this ENM was re-read during that time by
		 * comparing the object's script time with the one from above.
		 */
		object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM, object_name);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_enm_activate_deactivate_thread: "
			    "could not find ENM %s after running script",
			    object_name);
			goto done;
		}

		if (object->nwamd_script_time.tv_sec != now.tv_sec ||
		    object->nwamd_script_time.tv_usec != now.tv_usec) {
			nlog(LOG_INFO, "nwamd_enm_activate_deactivate_thread: "
			    "ENM %s has been refreshed, nothing to do",
			    object_name);
			nwamd_object_release(object);
			goto done;
		}
		(void) gettimeofday(&object->nwamd_script_time, NULL);

err:
		/*
		 * If script execution fails and we're not destroying the
		 * object, go to maintenance.
		 */
		if (ret != 0) {
			nlog(LOG_ERR, "nwamd_enm_activate_deactivate_thread: "
			    "execution of '%s' failed for ENM %s",
			    script, object_name);
			if (object->nwamd_object_aux_state !=
			    NWAM_AUX_STATE_UNINITIALIZED) {
				state = NWAM_STATE_MAINTENANCE;
				aux_state = NWAM_AUX_STATE_METHOD_FAILED;
			} else {
				state = NWAM_STATE_UNINITIALIZED;
				aux_state = NWAM_AUX_STATE_UNINITIALIZED;
			}
		} else {
			if (going_online) {
				state = NWAM_STATE_ONLINE;
				aux_state = NWAM_AUX_STATE_ACTIVE;
			} else {
				disable_succeeded = B_TRUE;
			}
		}
	}

	if (disable_succeeded) {
		/*
		 * If aux state is "manual disable", we know
		 * this was a disable request, otherwise it was
		 * _fini request or a condition satisfaction
		 * failure.
		 */
		switch (object->nwamd_object_aux_state) {
		case NWAM_AUX_STATE_MANUAL_DISABLE:
			state = NWAM_STATE_DISABLED;
			aux_state = NWAM_AUX_STATE_MANUAL_DISABLE;
			break;
		case NWAM_AUX_STATE_UNINITIALIZED:
			state = NWAM_STATE_UNINITIALIZED;
			aux_state = NWAM_AUX_STATE_UNINITIALIZED;
			break;
		default:
			state = NWAM_STATE_OFFLINE;
			aux_state = NWAM_AUX_STATE_CONDITIONS_NOT_MET;
			break;
		}
	}

	/* If state/aux state are uninitialized/unintialized, destroy the ENM */
	if (state == NWAM_STATE_UNINITIALIZED &&
	    aux_state == NWAM_AUX_STATE_UNINITIALIZED) {
		object->nwamd_object_state = state;
		object->nwamd_object_aux_state = aux_state;
		(void) nwamd_object_release_and_destroy_after_preserve(object);
	} else {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    object->nwamd_object_name, state, aux_state);
		(void) nwamd_object_release_after_preserve(object);
	}

done:
	/* object_name was malloc() before this thread was created, free() it */
	free(object_name);
	free(argv);
	free(copy);
	nwam_value_free(scriptval);
	return (NULL);
}

/*
 * Run start/stop method for ENM in a separate thread.  The object lock is not
 * held across threads, so we duplicate the object name for the method
 * execution thread.  Returns true if thread is successfully launched.
 */
boolean_t
nwamd_enm_run_method(nwamd_object_t object)
{
	char *name;
	pthread_t script;

	/*
	 * Launch separate thread to wait for execution of script
	 * to complete.  Do not hold object lock across threads.
	 */
	if ((name = strdup(object->nwamd_object_name)) == NULL) {
		nlog(LOG_ERR, "nwamd_enm_run_method: %s: out of memory",
		    object->nwamd_object_name);
		return (B_FALSE);
	}

	if (pthread_create(&script, NULL,
	    nwamd_enm_activate_deactivate_thread, name) != 0) {
		nlog(LOG_ERR, "nwamd_enm_run_method: could not create "
		    "enm script thread for %s", name);
		free(name);
		return (B_FALSE);
	}
	/* "name" will be freed by the newly-created thread. */

	/* detach thread so that it doesn't become a zombie */
	(void) pthread_detach(script);

	return (B_TRUE);
}

/*
 * Activate the ENM, either in response to an enable event or conditions
 * being satisfied.
 */
static void
nwamd_enm_activate(const char *object_name)
{
	nwamd_object_t object;
	nwam_value_t fmrival;
	char *fmri, *smf_state;
	int ret;
	nwam_enm_handle_t enmh;
	nwam_state_t state;
	nwam_aux_state_t aux_state;
	nwam_error_t err;
	boolean_t ran_method = B_FALSE;

	object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM, object_name);
	if (object == NULL) {
		nlog(LOG_ERR, "nwamd_enm_activate: could not find ENM %s",
		    object_name);
		return;
	}
	state = object->nwamd_object_state;
	aux_state = object->nwamd_object_aux_state;
	enmh = object->nwamd_object_handle;

	nlog(LOG_DEBUG, "nwamd_enm_activate: activating ENM %s",
	    object->nwamd_object_name);

	err = nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_FMRI, &fmrival);
	switch (err) {
	case NWAM_SUCCESS:

		if (nwam_value_get_string(fmrival, &fmri) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_enm_activate: could not retrieve "
			    "FMRI string for ENM %s",
			    object->nwamd_object_name);
			nwam_value_free(fmrival);
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_INVALID_CONFIG;
			break;
		}

		if ((smf_state = smf_get_state(fmri)) == NULL) {
			nlog(LOG_ERR, "nwamd_enm_activate: invalid FMRI %s "
			    "for ENM %s", fmri, object->nwamd_object_name);
			nwam_value_free(fmrival);
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_INVALID_CONFIG;
			break;
		}

		nlog(LOG_DEBUG, "nwamd_enm_activate: activating %s for ENM %s",
		    fmri, object->nwamd_object_name);

		if (strcmp(smf_state, SCF_STATE_STRING_ONLINE) == 0)
			ret = smf_restart_instance(fmri);
		else if (strcmp(smf_state, SCF_STATE_STRING_OFFLINE) == 0)
			ret = smf_restart_instance(fmri);
		else if (strcmp(smf_state, SCF_STATE_STRING_DISABLED) == 0)
			ret = smf_enable_instance(fmri, SMF_TEMPORARY);
		else
			ret = smf_restore_instance(fmri);

		if (ret == 0) {
			state = NWAM_STATE_ONLINE;
			aux_state = NWAM_AUX_STATE_ACTIVE;
		} else {
			nlog(LOG_ERR, "nwamd_enm_activate: failed to enable "
			    "FMRI %s for ENM %s", fmri,
			    object->nwamd_object_name);
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_METHOD_FAILED;
		}
		free(smf_state);
		nwam_value_free(fmrival);
		break;
	default:
		/*
		 * Must be a method-based ENM with start (and stop) script(s).
		 */
		if (!nwamd_enm_run_method(object)) {
			/* Could not launch method execution thread */
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_METHOD_FAILED;
		} else {
			ran_method = B_TRUE;
		}
		break;
	}

	if (state != object->nwamd_object_state ||
	    aux_state != object->nwamd_object_aux_state) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    object->nwamd_object_name, state, aux_state);
	}

	/*
	 * If the method thread was created, we drop the lock to the ENM
	 * object without decreasing the reference count, ensuring it will not
	 * be destroyed until method execution has completed.
	 */
	if (ran_method) {
		nwamd_object_release_and_preserve(object);
	} else {
		nwamd_object_release(object);
	}
}

/* Deactivates the ENM. */
static void
nwamd_enm_deactivate(const char *object_name)
{
	nwamd_object_t object;
	nwam_enm_handle_t enmh;
	nwam_value_t fmrival;
	char *fmri, *smf_state;
	int ret;
	nwam_state_t state;
	nwam_aux_state_t aux_state;
	boolean_t destroying = B_FALSE;

	object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM, object_name);
	if (object == NULL) {
		nlog(LOG_ERR, "nwamd_enm_deactivate: could not find ENM %s",
		    object_name);
		return;
	}

	state = object->nwamd_object_state;
	aux_state = object->nwamd_object_aux_state;
	enmh = object->nwamd_object_handle;
	state = object->nwamd_object_state;
	/* If destroying, we don't care about method failure/config err */
	destroying = (aux_state == NWAM_AUX_STATE_UNINITIALIZED);

	nlog(LOG_DEBUG, "nwamd_enm_deactivate: deactivating enm %s",
	    object->nwamd_object_name);

	if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_FMRI, &fmrival)
	    != NWAM_SUCCESS) {
		/*
		 * Must be a method-based ENM with start (and stop) script(s).
		 * Script execution thread will take care of the rest.
		 * If the method thread was created, we drop the lock to the ENM
		 * object without decreasing the reference count, ensuring it
		 * will not be destroyed until method execution has completed.
		 */
		if (nwamd_enm_run_method(object)) {
			nwamd_object_release_and_preserve(object);
			return;
		}
		/* Could not launch method execution thread */
		if (!destroying) {
			state = NWAM_STATE_MAINTENANCE;
			aux_state = NWAM_AUX_STATE_METHOD_FAILED;
		}
	} else {
		if (nwam_value_get_string(fmrival, &fmri) != NWAM_SUCCESS) {
			nlog(LOG_ERR,
			    "nwamd_enm_deactivate: could not retrieve "
			    "FMRI string for ENM %s",
			    object->nwamd_object_name);
			if (!destroying) {
				state = NWAM_STATE_MAINTENANCE;
				aux_state = NWAM_AUX_STATE_INVALID_CONFIG;
			}
		} else {
			if ((smf_state = smf_get_state(fmri)) == NULL) {
				nlog(LOG_ERR, "nwamd_enm_deactivate: invalid "
				    "FMRI %s for ENM %s", fmri,
				    object->nwamd_object_name);
				nwam_value_free(fmrival);
				if (!destroying) {
					state = NWAM_STATE_MAINTENANCE;
					aux_state =
					    NWAM_AUX_STATE_INVALID_CONFIG;
				}
				goto done;
			}
			free(smf_state);

			nlog(LOG_DEBUG, "nwamd_enm_deactivate: deactivating %s "
			    "for ENM %s", fmri, object->nwamd_object_name);

			ret = smf_disable_instance(fmri, SMF_TEMPORARY);

			if (ret != 0) {
				nlog(LOG_ERR, "nwamd_enm_deactivate: "
				    "smf_disable_instance(%s) failed for "
				    "ENM %s: %s", fmri,
				    object->nwamd_object_name,
				    scf_strerror(scf_error()));
				if (!destroying) {
					state = NWAM_STATE_MAINTENANCE;
					aux_state =
					    NWAM_AUX_STATE_METHOD_FAILED;
				}
			}
		}
		nwam_value_free(fmrival);
	}
done:
	if (state == object->nwamd_object_state &&
	    aux_state == object->nwamd_object_aux_state) {
		/*
		 * If aux state is "manual disable", we know
		 * this was a disable request, otherwise it was
		 * a _fini request or a condition satisfaction
		 * failure.
		 */
		switch (object->nwamd_object_aux_state) {
		case NWAM_AUX_STATE_MANUAL_DISABLE:
			state = NWAM_STATE_DISABLED;
			aux_state = NWAM_AUX_STATE_MANUAL_DISABLE;
			break;
		case NWAM_AUX_STATE_UNINITIALIZED:
			state = NWAM_STATE_UNINITIALIZED;
			aux_state = NWAM_AUX_STATE_UNINITIALIZED;
			break;
		default:
			state = NWAM_STATE_OFFLINE;
			aux_state = NWAM_AUX_STATE_CONDITIONS_NOT_MET;
			break;
		}
	}

	/* Only change state if we aren't destroying the ENM */
	if (!destroying && (state != object->nwamd_object_state ||
	    aux_state != object->nwamd_object_aux_state)) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    object->nwamd_object_name, state, aux_state);
	}

	/* If state/aux state are uninitialized/unintialized, destroy the ENM */
	if (state == NWAM_STATE_UNINITIALIZED &&
	    aux_state == NWAM_AUX_STATE_UNINITIALIZED) {
		(void) nwamd_object_release_and_destroy(object);
	} else {
		(void) nwamd_object_release(object);
	}
}

/*
 * Determine whether an ENM should be (de)activated.
 */
/* ARGSUSED1 */
static int
nwamd_enm_check(nwamd_object_t object, void *data)
{
	nwam_enm_handle_t enmh;
	nwam_value_t conditionval;
	int64_t eactivation;
	boolean_t enabled, satisfied;
	char **conditions;
	nwam_state_t state;
	uint_t nelem;

	state = object->nwamd_object_state;

	enmh = object->nwamd_object_handle;

	eactivation = enm_get_activation_mode(enmh);
	if (eactivation == -1)
		return (0);

	switch (eactivation) {
	case NWAM_ACTIVATION_MODE_MANUAL:
		enabled = enm_is_enabled(enmh);

		if (enabled) {
			nlog(LOG_DEBUG, "nwamd_enm_check: %s is enabled",
			    object->nwamd_object_name);
			switch (state) {
			case NWAM_STATE_ONLINE:
			case NWAM_STATE_MAINTENANCE:
				/* Do nothing */
				break;
			default:
				if (nwamd_enm_action(object->nwamd_object_name,
				    NWAM_ACTION_ENABLE) != 0) {
					nlog(LOG_ERR,
					    "nwamd_enm_check: enable failed "
					    "for enm %s",
					    object->nwamd_object_name);
				}
				break;
			}
		} else {
			nlog(LOG_DEBUG, "nwamd_enm_check: %s is disabled",
			    object->nwamd_object_name);
			switch (state) {
			case NWAM_STATE_ONLINE:
				if (nwamd_enm_action(object->nwamd_object_name,
				    NWAM_ACTION_DISABLE) != 0) {
					nlog(LOG_ERR, "nwamd_enm_check: "
					    "disable failed for enm %s",
					    object->nwamd_object_name);
				}
				break;
			case NWAM_STATE_MAINTENANCE:
				/* Do nothing */
				break;
			case NWAM_STATE_DISABLED:
				/* Do nothing */
				break;
			default:
				nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
				    object->nwamd_object_name,
				    NWAM_STATE_DISABLED,
				    NWAM_AUX_STATE_MANUAL_DISABLE);
				break;
			}
		}
		break;

	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		if (nwam_enm_get_prop_value(enmh,
		    NWAM_ENM_PROP_CONDITIONS, &conditionval) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_enm_check: could not retrieve "
			    "condition value");
			break;
		}
		if (nwam_value_get_string_array(conditionval,
		    &conditions, &nelem) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_enm_check: could not retrieve "
			    "condition value");
			nwam_value_free(conditionval);
			break;
		}
		satisfied = nwamd_check_conditions((uint64_t)eactivation,
		    conditions, nelem);

		nlog(LOG_DEBUG, "nwamd_enm_check: conditions for enm %s "
		    "%s satisfied", object->nwamd_object_name,
		    satisfied ? "is" : "is not");
		if (state != NWAM_STATE_ONLINE && satisfied) {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
			    object->nwamd_object_name,
			    NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_METHOD_RUNNING);
		}
		if (state == NWAM_STATE_ONLINE && !satisfied) {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
			    object->nwamd_object_name,
			    NWAM_STATE_ONLINE_TO_OFFLINE,
			    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
		}
		nwam_value_free(conditionval);
		break;

	}
	return (0);
}

void
nwamd_enm_check_conditions(void)
{
	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_ENM, nwamd_enm_check, NULL);
}

int
nwamd_enm_action(const char *enm, nwam_action_t action)
{
	nwamd_event_t event = nwamd_event_init_object_action
	    (NWAM_OBJECT_TYPE_ENM, enm, NULL, action);
	if (event == NULL)
		return (1);
	nwamd_event_enqueue(event);
	return (0);
}

/*
 * Event handling functions.
 */

/* Handle ENM initialization/refresh event */
void
nwamd_enm_handle_init_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwam_enm_handle_t enmh;
	nwam_error_t err;
	boolean_t manual_disabled = B_FALSE;

	if ((err = nwam_enm_read(event->event_object, 0, &enmh))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_enm_handle_init_event: could not "
		    "read object '%s': %s", event->event_object,
		    nwam_strerror(err));
		nwamd_event_do_not_send(event);
		return;
	}
	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM,
	    event->event_object)) != NULL) {
		nwam_enm_free(object->nwamd_object_handle);
		object->nwamd_object_handle = enmh;
	} else {
		object = nwamd_object_init(NWAM_OBJECT_TYPE_ENM,
		    event->event_object, enmh, NULL);
		object->nwamd_object_state = NWAM_STATE_OFFLINE;
		object->nwamd_object_aux_state =
		    NWAM_AUX_STATE_CONDITIONS_NOT_MET;
	}
	/* (Re)set script time to now as the object has just been (re)read */
	(void) gettimeofday(&object->nwamd_script_time, NULL);

	manual_disabled = (enm_get_activation_mode(enmh) ==
	    NWAM_ACTIVATION_MODE_MANUAL && !enm_is_enabled(enmh));

	/*
	 * If this ENM is ONLINE, and not manual and disabled (since in
	 * that case it was online but we've just set enabled = false as part
	 * of a disable action), then it is still active but refreshing.
	 * Change states to re-activate itself.
	 */
	if (!manual_disabled &&
	    object->nwamd_object_state == NWAM_STATE_ONLINE) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_METHOD_RUNNING);
	}
	nwamd_object_release(object);
}

/* Handle ENM finish event */
void
nwamd_enm_handle_fini_event(nwamd_event_t event)
{
	nwamd_event_t state_event;

	nlog(LOG_DEBUG, "nwamd_enm_handle_fini_event(%s)", event->event_object);

	/*
	 * Simulate a state event so that the state machine can correctly
	 * deactivate the ENM and free up the handle.
	 */
	state_event = nwamd_event_init_object_state(NWAM_OBJECT_TYPE_ENM,
	    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
	    NWAM_AUX_STATE_UNINITIALIZED);
	if (state_event == NULL) {
		nwamd_event_do_not_send(event);
		return;
	}
	nwamd_enm_handle_state_event(state_event);
	nwamd_event_fini(state_event);
	/*
	 * Do not free the handle and object.
	 * nwamd_enm_activate_deactivate_thread() and
	 * nwamd_enm_deactivate() does this after running the stop script
	 * and disabling the FMRI respectively.
	 */
}

void
nwamd_enm_handle_action_event(nwamd_event_t event)
{
	nwamd_object_t object;

	switch (event->event_msg->nwe_data.nwe_object_action.nwe_action) {
	case NWAM_ACTION_ENABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_enm_handle_action_event: "
			    "could not find enm %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_ONLINE) {
			nlog(LOG_DEBUG, "nwamd_enm_handle_action_event: "
			    "enm %s already online, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_METHOD_RUNNING);
		break;
	case NWAM_ACTION_DISABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_enm_handle_action_event: "
			    "could not find enm %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_DISABLED) {
			nlog(LOG_DEBUG, "nwamd_enm_handle_action_event: "
			    "enm %s already disabled, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_ENM,
		    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
		    NWAM_AUX_STATE_MANUAL_DISABLE);
		break;
	case NWAM_ACTION_ADD:
	case NWAM_ACTION_REFRESH:
		nwamd_enm_handle_init_event(event);
		break;
	case NWAM_ACTION_DESTROY:
		nwamd_enm_handle_fini_event(event);
		break;
	default:
		nlog(LOG_INFO, "nwam_enm_handle_action_event: "
		    "unexpected action");
		nwamd_event_do_not_send(event);
		break;
	}
}

void
nwamd_enm_handle_state_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwam_state_t new_state;
	nwam_aux_state_t new_aux_state;

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_ENM,
	    event->event_object)) == NULL) {
		nlog(LOG_ERR, "nwamd_enm_handle_state_event: "
		    "state event for nonexistent ENM %s", event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	new_state = event->event_msg->nwe_data.nwe_object_state.nwe_state;
	new_aux_state =
	    event->event_msg->nwe_data.nwe_object_state.nwe_aux_state;

	if (new_state == object->nwamd_object_state &&
	    new_aux_state == object->nwamd_object_aux_state) {
		nlog(LOG_DEBUG, "nwamd_enm_handle_state_event: "
		    "ENM %s already in state (%s , %s)",
		    object->nwamd_object_name, nwam_state_to_string(new_state),
		    nwam_aux_state_to_string(new_aux_state));
		nwamd_object_release(object);
		return;
	}

	object->nwamd_object_state = new_state;
	object->nwamd_object_aux_state = new_aux_state;

	nlog(LOG_DEBUG, "nwamd_enm_handle_state_event: changing state for ENM "
	    "%s to (%s , %s)", object->nwamd_object_name,
	    nwam_state_to_string(object->nwamd_object_state),
	    nwam_aux_state_to_string(object->nwamd_object_aux_state));

	nwamd_object_release(object);

	/*
	 * State machine for ENMs.
	 */
	switch (new_state) {
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		nwamd_enm_activate(event->event_object);
		break;
	case NWAM_STATE_ONLINE_TO_OFFLINE:
		nwamd_enm_deactivate(event->event_object);
		break;
	case NWAM_STATE_DISABLED:
	case NWAM_STATE_OFFLINE:
	case NWAM_STATE_UNINITIALIZED:
	case NWAM_STATE_MAINTENANCE:
	case NWAM_STATE_DEGRADED:
	default:
		/* do nothing */
		break;
	}
}
