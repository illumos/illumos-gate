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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _DISKMOND_CONF_H
#define	_DISKMOND_CONF_H

/*
 * Configuration File data
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <pthread.h>
#include <libnvpair.h>
#include <fm/fmd_api.h>
#include "dm_types.h"
#include "util.h"

#ifndef MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define	DEVICES_PREFIX "/devices"

#define	GLOBAL_PROP_LOG_LEVEL		"log-level"

/* Property names (and values) for the disk configuration file entity */
#define	DISK_PROP_DEVPATH		"dev-path"
#define	DISK_PROP_LOGNAME		"logical-path"
#define	DISK_PROP_FRUACTION		"fru-update-action"
#define	DISK_PROP_OTEMPACTION		"overtemp-action"
#define	DISK_PROP_STFAILACTION		"selftest-fail-action"
#define	DISK_PROP_SSMWEAROUTACTION	"ssm-wearout-action"

/* Properties for the "ap" subentity */
#define	DISK_AP_PROP_APID "path"

#define	DEVPATH_MINOR_SEPARATOR ':'

#define	DEFAULT_FAULT_POLLING_INTERVAL 3600	/* seconds */

#define	INDICATOR_FAULT_IDENTIFIER "FAULT"

typedef enum conf_err_e {
	E_NO_ERROR = 0,
	E_MULTIPLE_IND_LISTS_DEFINED,
	E_MULTIPLE_INDRULE_LISTS_DEFINED,
	E_INVALID_STATE_CHANGE,
	E_IND_MULTIPLY_DEFINED,
	E_IND_ACTION_REDUNDANT,
	E_IND_ACTION_CONFLICT,
	E_IND_MISSING_FAULT_ON,
	E_IND_MISSING_FAULT_OFF,
	E_INDRULE_REFERENCES_NONEXISTENT_IND_ACTION,
	E_DUPLICATE_STATE_TRANSITION
} conf_err_t;

typedef enum {
	INDICATOR_UNKNOWN,
	INDICATOR_ON,
	INDICATOR_OFF
} ind_state_t;

typedef enum {
	TS_NOT_RUNNING,
	TS_RUNNING,
	TS_EXIT_REQUESTED,
	TS_EXITED
} thread_state_t;

typedef struct ind_action {
	ind_state_t		ind_state;
	char			*ind_name;
	struct ind_action	*next;
} ind_action_t;

typedef struct state_transition {
	hotplug_state_t		begin;
	hotplug_state_t		end;
} state_transition_t;

typedef struct indrule {
	state_transition_t	strans;
	ind_action_t 		*action_list;
	struct indrule 		*next;
} indrule_t;

typedef struct indicator {
	ind_state_t		ind_state;
	char			*ind_name;
	char			*ind_instr_spec;
	struct indicator	*next;
} indicator_t;

typedef struct diskmon {
	/*
	 * Static configuration data
	 */
	nvlist_t		*props;
	char			*location;	/* descriptive location */
	nvlist_t		*app_props;
	indicator_t		*ind_list;
	indrule_t		*indrule_list;
	/*
	 * Dynamic data
	 */
	hotplug_state_t		state;

	/*
	 * Only one manager can be manipulating the
	 * state in the diskmon at one time (either the
	 * state-change manager or the fault-polling manager)
	 */
	pthread_mutex_t		manager_mutex;

	/*
	 * Set to true only during initialization, and
	 * cleared the next time a fru update needs to
	 * occur, this flag enabled an optimization of
	 * NOT calling libtopo for a configuration update
	 * when the DE starts up.  This allows a HUGE
	 * savings (since only a single snapshot-- the
	 * initial snapshot) is used as the source of
	 * the FRU information.
	 */
	boolean_t		initial_configuration;

	/* For the state-change manager: */

	/*
	 * Current state of the fault indicator.
	 */
	pthread_mutex_t		fault_indicator_mutex;
	ind_state_t		fault_indicator_state;

	/*
	 * Set to TRUE when a disk transitions to the CONFIGURED state
	 * and remains TRUE until the disk is physically removed.
	 */
	boolean_t		configured_yet;

	/*
	 * The number of disk hotplug state transitions since the disk
	 * was inserted.
	 */
	uint_t			state_change_count;

	/* Disk FRU (model, manufacturer, etc) information */
	pthread_mutex_t		fru_mutex;
	dm_fru_t		*frup;

	struct diskmon		*next;
} diskmon_t;

typedef struct cfgdata {
	nvlist_t 		*props;
	diskmon_t		*disk_list;
} cfgdata_t;

typedef struct namevalpr {
	char 			*name;
	char 			*value;
} namevalpr_t;


extern indicator_t 	*new_indicator(ind_state_t lstate, char *namep,
    char *actionp);
extern void		link_indicator(indicator_t **first,
    indicator_t *to_add);
extern void		ind_free(indicator_t *indp);

extern ind_action_t 	*new_indaction(ind_state_t state, char *namep);
extern void		link_indaction(ind_action_t **first,
    ind_action_t *to_add);
extern void		indaction_free(ind_action_t *lap);

extern indrule_t 	*new_indrule(state_transition_t *st,
    ind_action_t *actionp);
extern void		link_indrule(indrule_t **first, indrule_t *to_add);
extern void		indrule_free(indrule_t *lrp);

extern diskmon_t	*new_diskmon(nvlist_t *app_props, indicator_t *indp,
    indrule_t *indrp, nvlist_t *nvlp);
extern void		diskmon_free(diskmon_t *dmp);

extern dm_fru_t 	*new_dmfru(char *manu, char *modl, char *firmrev,
    char *serno, uint64_t capa);
extern void		dmfru_free(dm_fru_t *frup);

extern nvlist_t 	*namevalpr_to_nvlist(namevalpr_t *nvprp);

extern conf_err_t	check_state_transition(hotplug_state_t s1,
    hotplug_state_t s2);
extern conf_err_t	check_inds(indicator_t *indp);
extern conf_err_t	check_indactions(ind_action_t *indap);
extern conf_err_t	check_indrules(indrule_t *indrp,
    state_transition_t **offender);
extern conf_err_t	check_consistent_ind_indrules(indicator_t *indp,
    indrule_t *indrp, ind_action_t **offender);

extern void		cfgdata_add_diskmon(cfgdata_t *cfgp, diskmon_t *dmp);

extern void		conf_error_msg(conf_err_t err, char *buf, int buflen,
    void *arg);

extern const char	*dm_prop_lookup(nvlist_t *props, const char *prop_name);
extern int		dm_prop_lookup_int(nvlist_t *props,
    const char *prop_name, int *value);

extern int		config_init(void);
extern int		config_get(fmd_hdl_t *hdl, const fmd_prop_t *fmd_props);
extern void		config_fini(void);

extern const char *hotplug_state_string(hotplug_state_t state);

extern nvlist_t	*dm_global_proplist(void);

#ifdef __cplusplus
}
#endif

#endif /* _DISKMOND_CONF_H */
