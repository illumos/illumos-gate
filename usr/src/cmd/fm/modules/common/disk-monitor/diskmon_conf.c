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
 * Disk & Indicator Monitor configuration file support routines
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "disk_monitor.h"
#include "util.h"
#include "topo_gather.h"

extern log_class_t g_verbose;

const char *
hotplug_state_string(hotplug_state_t state)
{
	switch (state & ~HPS_FAULTED) {
	default:
	case HPS_UNKNOWN:
		return ("Unknown");
	case HPS_ABSENT:
		return ("Absent");
	case HPS_PRESENT:
		return ("Present");
	case HPS_CONFIGURED:
		return ("Configured");
	case HPS_UNCONFIGURED:
		return ("Unconfigured");
	}
}

void
conf_error_msg(conf_err_t err, char *buf, int buflen, void *arg)
{
	switch (err) {
	case E_MULTIPLE_IND_LISTS_DEFINED:
		(void) snprintf(buf, buflen, "Multiple Indicator lists "
		    "defined");
		break;
	case E_MULTIPLE_INDRULE_LISTS_DEFINED:
		(void) snprintf(buf, buflen, "Multiple Indicator rule lists "
		    "defined");
		break;
	case E_INVALID_STATE_CHANGE:
		(void) snprintf(buf, buflen, "Invalid state change");
		break;
	case E_IND_MULTIPLY_DEFINED:
		(void) snprintf(buf, buflen,
		    "Multiple Indicator definitions (name & state) detected");
		break;
	case E_IND_ACTION_REDUNDANT:
		(void) snprintf(buf, buflen, "Redundant Indicator actions "
		    "specified");
		break;
	case E_IND_ACTION_CONFLICT:
		(void) snprintf(buf, buflen, "Indicator action conflict (+/- "
		    "same Indicator) found");
		break;
	case E_IND_MISSING_FAULT_ON:
		(void) snprintf(buf, buflen, "Missing declaration of `+"
		    INDICATOR_FAULT_IDENTIFIER "'");
		break;
	case E_IND_MISSING_FAULT_OFF:
		(void) snprintf(buf, buflen, "Missing declaration of `-"
		    INDICATOR_FAULT_IDENTIFIER "'");
		break;
	case E_INDRULE_REFERENCES_NONEXISTENT_IND_ACTION:
		(void) snprintf(buf, buflen, "`%c%s': Undefined Indicator in "
		    BAY_IND_ACTION " property",
		    (((ind_action_t *)arg)->ind_state == INDICATOR_ON)
		    ? '+' : '-',
		    ((ind_action_t *)arg)->ind_name);
		break;
	case E_DUPLICATE_STATE_TRANSITION:
		(void) snprintf(buf, buflen, "Duplicate state transition "
		    "(%s -> %s)",
		    hotplug_state_string(((state_transition_t *)arg)->begin),
		    hotplug_state_string(((state_transition_t *)arg)->end));
		break;
	default:
		(void) snprintf(buf, buflen, "Unknown error");
		break;
	}
}

static int
string_to_integer(const char *prop, int *value)
{
	long val;

	errno = 0;

	val = strtol(prop, NULL, 0);

	if (val == 0 && errno != 0)
		return (-1);
	else if (val > INT_MAX || val < INT_MIN) {
		errno = ERANGE;
		return (-1);
	}

	if (value != NULL)
		*value = (int)val;

	return (0);
}

const char *
dm_prop_lookup(nvlist_t *props, const char *prop_name)
{
	char *str;

	if (nvlist_lookup_string(props, prop_name, &str) == 0)
		return ((const char *)str);
	else
		return (NULL);
}

int
dm_prop_lookup_int(nvlist_t *props, const char *prop_name, int *value)
{
	const char *prop = dm_prop_lookup(props, prop_name);

	if (prop == NULL)
		return (-1);

	return (string_to_integer(prop, value));
}

nvlist_t *
namevalpr_to_nvlist(namevalpr_t *nvprp)
{
	nvlist_t *nvlp = NULL;

	if (nvlist_alloc(&nvlp, NV_UNIQUE_NAME, 0) != 0) {
		return (NULL);
	}

	if (nvlist_add_string(nvlp, nvprp->name, nvprp->value) != 0) {
		nvlist_free(nvlp);
		return (NULL);
	}

	return (nvlp);
}

indicator_t *
new_indicator(ind_state_t lstate, char *namep, char *actionp)
{
	indicator_t *newindicator =
	    (indicator_t *)dmalloc(sizeof (indicator_t));
	newindicator->ind_state = lstate;
	newindicator->ind_name = namep ? dstrdup(namep) : NULL;
	newindicator->ind_instr_spec = actionp ? dstrdup(actionp) : NULL;
	newindicator->next = NULL;
	return (newindicator);
}

void
link_indicator(indicator_t **first, indicator_t *to_add)
{
	indicator_t *travptr;
	dm_assert(first != NULL);

	if (*first == NULL)
		*first = to_add;
	else {
		travptr = *first;
		while (travptr->next != NULL) {
			travptr = travptr->next;
		}
		travptr->next = to_add;
	}
}

void
ind_free(indicator_t *indp)
{
	indicator_t *nextp;

	while (indp != NULL) {
		nextp = indp->next;
		if (indp->ind_name)
			dstrfree(indp->ind_name);
		if (indp->ind_instr_spec)
			dstrfree(indp->ind_instr_spec);
		dfree(indp, sizeof (indicator_t));
		indp = nextp;
	}
}

ind_action_t *
new_indaction(ind_state_t state, char *namep)
{
	ind_action_t *lap = (ind_action_t *)dmalloc(sizeof (ind_action_t));
	lap->ind_state = state;
	lap->ind_name = namep ? dstrdup(namep) : NULL;
	lap->next = NULL;
	return (lap);
}

void
link_indaction(ind_action_t **first, ind_action_t *to_add)
{
	ind_action_t *travptr;
	dm_assert(first != NULL);

	if (*first == NULL)
		*first = to_add;
	else {
		travptr = *first;
		while (travptr->next != NULL) {
			travptr = travptr->next;
		}
		travptr->next = to_add;
	}
}

void
indaction_free(ind_action_t *lap)
{
	ind_action_t *nextp;

	/* Free the whole list */
	while (lap != NULL) {
		nextp = lap->next;
		if (lap->ind_name)
			dstrfree(lap->ind_name);
		dfree(lap, sizeof (ind_action_t));
		lap = nextp;
	}
}

indrule_t *
new_indrule(state_transition_t *st, ind_action_t *actionp)
{
	indrule_t *lrp = (indrule_t *)dmalloc(sizeof (indrule_t));
	if (st != NULL)
		lrp->strans = *st;
	lrp->action_list = actionp;
	lrp->next = NULL;
	return (lrp);
}

void
link_indrule(indrule_t **first, indrule_t *to_add)
{
	indrule_t *travptr;
	dm_assert(first != NULL);

	if (*first == NULL)
		*first = to_add;
	else {
		travptr = *first;
		while (travptr->next != NULL) {
			travptr = travptr->next;
		}
		travptr->next = to_add;
	}
}

void
indrule_free(indrule_t *lrp)
{
	indrule_t *nextp;

	/* Free the whole list */
	while (lrp != NULL) {
		nextp = lrp->next;
		if (lrp->action_list)
			indaction_free(lrp->action_list);
		dfree(lrp, sizeof (indrule_t));
		lrp = nextp;
	}
}

dm_fru_t *
new_dmfru(char *manu, char *modl, char *firmrev, char *serno, uint64_t capa)
{
	dm_fru_t *frup = (dm_fru_t *)dzmalloc(sizeof (dm_fru_t));

	bcopy(manu, frup->manuf, MIN(sizeof (frup->manuf), strlen(manu) + 1));
	bcopy(modl, frup->model, MIN(sizeof (frup->model), strlen(modl) + 1));
	bcopy(firmrev, frup->rev, MIN(sizeof (frup->rev), strlen(firmrev) + 1));
	bcopy(serno, frup->serial,
	    MIN(sizeof (frup->serial), strlen(serno) + 1));
	frup->size_in_bytes = capa;
	return (frup);
}

void
dmfru_free(dm_fru_t *frup)
{
	dfree(frup, sizeof (dm_fru_t));
}

diskmon_t *
new_diskmon(nvlist_t *app_props, indicator_t *indp, indrule_t *indrp,
    nvlist_t *nvlp)
{
	diskmon_t *dmp = (diskmon_t *)dmalloc(sizeof (diskmon_t));

	if (nvlp != NULL)
		dmp->props = nvlp;
	else
		(void) nvlist_alloc(&dmp->props, NV_UNIQUE_NAME, 0);

	if (app_props)
		dmp->app_props = app_props;
	else
		(void) nvlist_alloc(&dmp->app_props, NV_UNIQUE_NAME, 0);
	dmp->ind_list = indp;
	dmp->indrule_list = indrp;

	dm_assert(pthread_mutex_init(&dmp->manager_mutex, NULL) == 0);

	dmp->state = HPS_UNKNOWN;

	dmp->initial_configuration = B_TRUE;

	dm_assert(pthread_mutex_init(&dmp->fault_indicator_mutex, NULL) == 0);
	dmp->fault_indicator_state = INDICATOR_UNKNOWN;

	dmp->configured_yet = B_FALSE;
	dmp->state_change_count = 0;

	dm_assert(pthread_mutex_init(&dmp->fru_mutex, NULL) == 0);
	dmp->frup = NULL;

	dmp->next = NULL;
	return (dmp);
}

void
diskmon_free(diskmon_t *dmp)
{
	diskmon_t *nextp;

	/* Free the whole list */
	while (dmp != NULL) {
		nextp = dmp->next;

		nvlist_free(dmp->props);
		if (dmp->location)
			dstrfree(dmp->location);
		if (dmp->ind_list)
			ind_free(dmp->ind_list);
		if (dmp->indrule_list)
			indrule_free(dmp->indrule_list);
		nvlist_free(dmp->app_props);
		if (dmp->frup)
			dmfru_free(dmp->frup);
		dfree(dmp, sizeof (diskmon_t));

		dmp = nextp;
	}
}

static cfgdata_t *
new_cfgdata(namevalpr_t *nvp, diskmon_t *dmp)
{
	cfgdata_t *cdp = (cfgdata_t *)dzmalloc(sizeof (cfgdata_t));

	if (nvp != NULL)
		cdp->props = namevalpr_to_nvlist(nvp);
	else if (nvlist_alloc(&cdp->props, NV_UNIQUE_NAME, 0) != 0) {
		return (NULL);
	}

	if (dmp != NULL)
		cdp->disk_list = dmp;
	return (cdp);

}

static void
cfgdata_add_namevalpr(cfgdata_t *cfgp, namevalpr_t *nvp)
{
	if (cfgp->props == NULL) {
		(void) nvlist_alloc(&cfgp->props, NV_UNIQUE_NAME, 0);
	}
	(void) nvlist_add_string(cfgp->props, nvp->name, nvp->value);
}

void
cfgdata_add_diskmon(cfgdata_t *cfgp, diskmon_t *dmp)
{
	if (cfgp->disk_list == NULL) {
		cfgp->disk_list = dmp;
	} else {
		diskmon_t *disklist = cfgp->disk_list;

		while (disklist->next != NULL)
			disklist = disklist->next;

		disklist->next = dmp;
	}
}

static void
cfgdata_free(cfgdata_t *cdp)
{
	nvlist_free(cdp->props);
	diskmon_free(cdp->disk_list);
	dfree(cdp, sizeof (cfgdata_t));
}

conf_err_t
check_indactions(ind_action_t *indrp)
{
	char *buf;
	conf_err_t rv = E_NO_ERROR;
	nvlist_t *nvp = NULL;
	int len;

	(void) nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);

	/*
	 * Check indicator actions for conflicts
	 */
	while (indrp != NULL && rv == E_NO_ERROR) {
		len = strlen(indrp->ind_name) + 2;
		buf = dmalloc(len);
		(void) snprintf(buf, len, "%c%s",
		    indrp->ind_state == INDICATOR_ON ? '+' : '-',
		    indrp->ind_name);
		switch (nvlist_lookup_boolean(nvp, buf)) {
		case ENOENT:
			(void) nvlist_add_boolean(nvp, buf);
			break;
		case 0:
			rv = E_IND_ACTION_REDUNDANT;
			break;
		default:
			break;
		}

		/* Look for the opposite action.  If found, that's an error */
		(void) snprintf(buf, len, "%c%s",
		    indrp->ind_state == INDICATOR_ON ? '-' : '+',
		    indrp->ind_name);
		switch (nvlist_lookup_boolean(nvp, buf)) {
		case ENOENT:
			break;
		case 0:
			rv = E_IND_ACTION_CONFLICT;
			break;
		default:
			break;
		}
		dfree(buf, len);
		indrp = indrp->next;
	}

	nvlist_free(nvp);
	return (rv);
}

conf_err_t
check_inds(indicator_t *indp)
{
	char *buf;
	conf_err_t rv = E_NO_ERROR;
	nvlist_t *nvp = NULL;
	int len;
	boolean_t fault_on = B_FALSE, fault_off = B_FALSE;

	(void) nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);

	/*
	 * Check inds for multiple definitions (same identifier or same action)
	 */
	while (indp != NULL && rv == E_NO_ERROR) {
		len = strlen(indp->ind_name) + 2;
		buf = dmalloc(len);
		(void) snprintf(buf, len, "%c%s",
		    indp->ind_state == INDICATOR_ON ? '+' : '-',
		    indp->ind_name);

		/* Keep track of the +/-FAULT for checking later */
		if (strcasecmp(buf, "+" INDICATOR_FAULT_IDENTIFIER) == 0)
			fault_on = B_TRUE;
		else if (strcasecmp(buf, "-" INDICATOR_FAULT_IDENTIFIER) == 0)
			fault_off = B_TRUE;

		switch (nvlist_lookup_boolean(nvp, buf)) {
		case ENOENT:
			(void) nvlist_add_boolean(nvp, buf);
			break;
		case 0:
			rv = E_IND_MULTIPLY_DEFINED;
			break;
		default:
			break;
		}
		dfree(buf, len);
		indp = indp->next;
	}

	/*
	 * Make sure we have a -FAULT and +FAULT
	 */
	if (!fault_on)
		rv = E_IND_MISSING_FAULT_ON;
	else if (!fault_off)
		rv = E_IND_MISSING_FAULT_OFF;

	nvlist_free(nvp);
	return (rv);
}

conf_err_t
check_indrules(indrule_t *indrp, state_transition_t **offender)
{
	char buf[32];
	conf_err_t rv = E_NO_ERROR;
	nvlist_t *nvp = NULL;

	/*
	 * Ensure that no two rules have the same state transitions.
	 */

	(void) nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);

	while (indrp != NULL && rv == E_NO_ERROR) {
		(void) snprintf(buf, sizeof (buf), "%d-%d",
		    (int)indrp->strans.begin, (int)indrp->strans.end);
		switch (nvlist_lookup_boolean(nvp, buf)) {
		case 0:
			*offender = &indrp->strans;
			rv = E_DUPLICATE_STATE_TRANSITION;
			break;
		case ENOENT:
			(void) nvlist_add_boolean(nvp, buf);
			break;
		default:
			break;
		}
		indrp = indrp->next;
	}

	nvlist_free(nvp);
	return (rv);
}


conf_err_t
check_consistent_ind_indrules(indicator_t *indp, indrule_t *indrp,
    ind_action_t **offender)
{
	char *buf;
	conf_err_t rv = E_NO_ERROR;
	nvlist_t *nvp = NULL;
	ind_action_t *alp;
	int len;

	/*
	 * Ensure that every indicator action referenced in each ruleset
	 * exists in the indicator list given.
	 */

	(void) nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);

	while (indp != NULL) {
		len = strlen(indp->ind_name) + 2;
		buf = dmalloc(len);
		(void) snprintf(buf, len, "%c%s",
		    indp->ind_state == INDICATOR_ON ? '+' : '-',
		    indp->ind_name);
		(void) nvlist_add_boolean(nvp, buf);
		dfree(buf, len);
		indp = indp->next;
	}

	while (indrp != NULL && rv == E_NO_ERROR) {
		alp = indrp->action_list;
		while (alp != NULL && rv == E_NO_ERROR) {
			len = strlen(alp->ind_name) + 2;
			buf = dmalloc(len);
			(void) snprintf(buf, len, "%c%s",
			    alp->ind_state == INDICATOR_ON ? '+' : '-',
			    alp->ind_name);

			switch (nvlist_lookup_boolean(nvp, buf)) {
			case 0:		/* Normal case */
				break;
			case ENOENT:
				*offender = alp;
				rv =
				    E_INDRULE_REFERENCES_NONEXISTENT_IND_ACTION;
				break;
			default:
				break;
			}
			dfree(buf, len);
			alp = alp->next;
		}
		indrp = indrp->next;
	}

	nvlist_free(nvp);
	return (rv);
}

conf_err_t
check_state_transition(hotplug_state_t s1, hotplug_state_t s2)
{
	/*
	 * The following are valid transitions:
	 *
	 * HPS_ABSENT -> HPS_PRESENT
	 * HPS_ABSENT -> HPS_CONFIGURED
	 * HPS_PRESENT -> HPS_CONFIGURED
	 * HPS_PRESENT -> HPS_ABSENT
	 * HPS_CONFIGURED -> HPS_UNCONFIGURED
	 * HPS_CONFIGURED -> HPS_ABSENT
	 * HPS_UNCONFIGURED -> HPS_ABSENT
	 * HPS_UNCONFIGURED -> HPS_CONFIGURED
	 *
	 */
	if (s1 == HPS_ABSENT && s2 != HPS_PRESENT && s2 != HPS_CONFIGURED)
		return (E_INVALID_STATE_CHANGE);
	else if (s1 == HPS_PRESENT && (s2 != HPS_CONFIGURED &&
	    s2 != HPS_ABSENT))
		return (E_INVALID_STATE_CHANGE);
	else if (s1 == HPS_CONFIGURED && (s2 != HPS_UNCONFIGURED &&
	    s2 != HPS_ABSENT))
		return (E_INVALID_STATE_CHANGE);
	else if (s1 == HPS_UNCONFIGURED && (s2 != HPS_ABSENT &&
	    s2 != HPS_CONFIGURED))
		return (E_INVALID_STATE_CHANGE);
	else
		return (E_NO_ERROR);
}

static void
print_inds(indicator_t *indp, FILE *fp, char *prefix)
{
	char plusminus;

	(void) fprintf(fp, "%sindicators {\n", prefix);
	while (indp != NULL) {
		plusminus = (indp->ind_state == INDICATOR_ON) ? '+' : '-';
		(void) fprintf(fp, "%s\t%c%s = \"%s\"\n", prefix, plusminus,
		    indp->ind_name, indp->ind_instr_spec);
		indp = indp->next;
	}
	(void) fprintf(fp, "%s}\n", prefix);
}

static void
print_indrules(indrule_t *lrp, FILE *fp, char *prefix)
{
	char plusminus;
	ind_action_t *lap;

	(void) fprintf(fp, "%sindicator_rules {\n", prefix);
	while (lrp != NULL) {
		(void) fprintf(fp, "%s\t%12s -> %12s\t{ ", prefix,
		    hotplug_state_string(lrp->strans.begin),
		    hotplug_state_string(lrp->strans.end));
		lap = lrp->action_list;
		while (lap != NULL) {
			plusminus = (lap->ind_state == INDICATOR_ON)
			    ? '+' : '-';
			(void) fprintf(fp, "%c%s", plusminus, lap->ind_name);
			lap = lap->next;
			if (lap != NULL)
				(void) fprintf(fp, ", ");
		}
		(void) fprintf(fp, " }\n");
		lrp = lrp->next;
	}
	(void) fprintf(fp, "%s}\n", prefix);
}

static void
print_props(nvlist_t *nvlp, FILE *fp, char *prefix)
{
	nvpair_t *nvp = nvlist_next_nvpair(nvlp, NULL);
	char *name, *str;

	while (nvp != NULL) {
		dm_assert(nvpair_type(nvp) == DATA_TYPE_STRING);
		name = nvpair_name(nvp);
		(void) nvlist_lookup_string(nvlp, name, &str);
		(void) fprintf(fp, "%s%s = \"%s\"\n", prefix, name, str);
		nvp = nvlist_next_nvpair(nvlp, nvp);
	}
}

static void
print_ap(nvlist_t *dpp, FILE *fp, char *prefix)
{
	int len = strlen(prefix) + 2;
	char *buf = dmalloc(len);

	(void) snprintf(buf, len, "%s\t", prefix);

	(void) fprintf(fp, "%sap_props {\n", prefix);
	print_props(dpp, fp, buf);
	(void) fprintf(fp, "%s}\n", prefix);

	dfree(buf, len);
}

static void
print_disks(diskmon_t *dmp, FILE *fp, char *prefix)
{
	int len = strlen(prefix) + 2;
	char *buf = dmalloc(len);

	(void) snprintf(buf, len, "%s\t", prefix);

	while (dmp != NULL) {
		(void) fprintf(fp, "%sdisk \"%s\" {\n", prefix, dmp->location);
		if (dmp->props) {
			print_props(dmp->props, fp, buf);
		}
		if (dmp->app_props) {
			print_ap(dmp->app_props, fp, buf);
		}
		(void) fprintf(fp, "%s\n", prefix);
		print_inds(dmp->ind_list, fp, buf);
		(void) fprintf(fp, "%s\n", prefix);
		print_indrules(dmp->indrule_list, fp, buf);
		(void) fprintf(fp, "%s}\n", prefix);

		if (dmp->next != NULL)
			(void) fprintf(fp, "%s\n", prefix);

		dmp = dmp->next;
	}

	dfree(buf, len);
}

static void
print_cfgdata(cfgdata_t *cfgp, FILE *fp, char *prefix)
{
	/* First, print the properties, then the disks */

	print_props(cfgp->props, fp, prefix);
	(void) fprintf(fp, "%s\n", prefix);
	print_disks(cfgp->disk_list, fp, prefix);
}

int
config_init(void)
{
	if (init_configuration_from_topo() == 0) {
		config_data = new_cfgdata(NULL, NULL);
		return (0);
	}
	return (-1);
}

int
config_get(fmd_hdl_t *hdl, const fmd_prop_t *fmd_props)
{
	int err, i = 0;
	char *str = NULL;
	namevalpr_t nvp;
	uint64_t u64;
	boolean_t intfound = B_FALSE, strfound = B_FALSE;
#define	INT64_BUF_LEN 128
	char buf[INT64_BUF_LEN];

	u64 = fmd_prop_get_int32(hdl, GLOBAL_PROP_LOG_LEVEL);
	g_verbose = (int)u64;

	err = update_configuration_from_topo(hdl, NULL);

	/* Pull in the properties from the DE configuration file */
	while (fmd_props[i].fmdp_name != NULL) {

		nvp.name = (char *)fmd_props[i].fmdp_name;

		switch (fmd_props[i].fmdp_type) {
		case FMD_TYPE_UINT32:
		case FMD_TYPE_INT32:
			intfound = B_TRUE;
			u64 = fmd_prop_get_int32(hdl, fmd_props[i].fmdp_name);
			break;
		case FMD_TYPE_UINT64:
		case FMD_TYPE_INT64:
			intfound = B_TRUE;
			u64 = fmd_prop_get_int64(hdl, fmd_props[i].fmdp_name);
			break;
		case FMD_TYPE_STRING:
			strfound = B_TRUE;
			str = fmd_prop_get_string(hdl, fmd_props[i].fmdp_name);
			break;

		}

		if (intfound) {
			(void) snprintf(buf, INT64_BUF_LEN, "0x%llx", u64);
			nvp.value = buf;
			intfound = B_FALSE;
		} else if (strfound) {
			nvp.value = str;
		}

		log_msg(MM_CONF, "Adding property `%s' with value `%s'\n",
		    nvp.name, nvp.value);

		cfgdata_add_namevalpr(config_data, &nvp);

		if (strfound) {
			strfound = B_FALSE;
			fmd_prop_free_string(hdl, str);
		}


		i++;
	}

	if ((g_verbose & (MM_CONF|MM_OTHER)) == (MM_CONF|MM_OTHER))
		print_cfgdata(config_data, stderr, "");

	return (err);
}

void
config_fini(void)
{
	fini_configuration_from_topo();
	cfgdata_free(config_data);
	config_data = NULL;
}

nvlist_t *
dm_global_proplist(void)
{
	return (config_data->props);
}
