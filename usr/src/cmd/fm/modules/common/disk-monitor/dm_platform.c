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

#include <ctype.h>
#include <libipmi.h>
#include <libnvpair.h>
#include <libuutil.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "diskmon_conf.h"
#include "dm_platform.h"
#include "util.h"

/* For the purposes of disk capacity, a <X>B is 1000x, not 1024x */
#define	ONE_KILOBYTE 1000.0
#define	ONE_MEGABYTE (ONE_KILOBYTE * 1000)
#define	ONE_GIGABYTE (ONE_MEGABYTE * 1000)
#define	ONE_TERABYTE (ONE_GIGABYTE * 1000)
#define	ONE_PETABYTE (ONE_TERABYTE * 1000)

static ipmi_handle_t *g_ipmi_hdl;

typedef enum {
	IPMI_CACHE_SENSOR,
	IPMI_CACHE_FRU
} ipmi_cache_type_t;

typedef struct ipmi_cache_entry {
	ipmi_cache_type_t			ic_type;
	uu_list_node_t				ic_node;
	union {
		ipmi_set_sensor_reading_t	ic_sensor;
		ipmi_sunoem_fru_t		ic_fru;
	} ic_data;
} ipmi_cache_entry_t;

static pthread_mutex_t g_ipmi_mtx = PTHREAD_MUTEX_INITIALIZER;
static uu_list_pool_t *g_ipmi_cache_pool;
static uu_list_t *g_ipmi_cache;

/*
 * The textual strings that are used in the actions may be one of the
 * following forms:
 *
 * [1] `fru gid=<n> hdd=<m>'
 * [2] `sensor id=<x> assert=<y> deassert=<z>'
 *
 * The generic parser will take a string and spit out the first token
 * (e.g. `fru' or `sensor') and an nvlist that contains the key-value
 * pairs in the rest of the string.  The assumption is that there are
 * no embedded spaces or tabs in the keys or values.
 */

static boolean_t
isnumber(const char *str)
{
	boolean_t hex = B_FALSE;
	int digits = 0;

	if (strncasecmp(str, "0x", 2) == 0) {
		hex = B_TRUE;
		str += 2;
	} else if (*str == '-' || *str == '+') {
		str++;
	}

	while (*str != 0) {
		if ((hex && !isxdigit(*str)) ||
		    (!hex && !isdigit(*str))) {
			return (B_FALSE);
		}

		str++;
		digits++;
	}

	return ((digits == 0) ? B_FALSE : B_TRUE);
}

static void
tolowerString(char *str)
{
	while (*str != 0) {
		*str = tolower(*str);
		str++;
	}
}

static boolean_t
parse_action_string(const char *actionString, char **cmdp, nvlist_t **propsp)
{
	char *action;
	char *tok, *lasts, *eq;
	int actionlen;
	boolean_t rv = B_TRUE;

	if (nvlist_alloc(propsp, NV_UNIQUE_NAME, 0) != 0)
		return (B_FALSE);

	actionlen = strlen(actionString) + 1;
	action = dstrdup(actionString);

	*cmdp = NULL;

	if ((tok = strtok_r(action, " \t", &lasts)) != NULL) {

		*cmdp = dstrdup(tok);

		while (rv && (tok = strtok_r(NULL, " \t", &lasts)) != NULL) {

			/* Look for a name=val construct */
			if ((eq = strchr(tok, '=')) != NULL && eq[1] != 0) {

				*eq = 0;
				eq++;

				/*
				 * Convert token to lowercase to preserve
				 * case-insensitivity, because nvlist doesn't
				 * do case-insensitive lookups
				 */
				tolowerString(tok);

				if (isnumber(eq)) {
					/* Integer property */

					if (nvlist_add_uint64(*propsp, tok,
					    strtoull(eq, NULL, 0)) != 0)
						rv = B_FALSE;
				} else {
					/* String property */

					if (nvlist_add_string(*propsp, tok,
					    eq) != 0)
						rv = B_FALSE;
				}
			} else if (eq == NULL) {
				/* Boolean property */
				if (nvlist_add_boolean(*propsp, tok) != 0)
					rv = B_FALSE;
			} else /* Parse error (`X=' is invalid) */
				rv = B_FALSE;
		}
	} else
		rv = B_FALSE;

	dfree(action, actionlen);
	if (!rv) {
		if (*cmdp) {
			dstrfree(*cmdp);
			*cmdp = NULL;
		}
		nvlist_free(*propsp);
		*propsp = NULL;
	}
	return (rv);
}

static int
platform_update_fru(nvlist_t *props, dm_fru_t *frup)
{
	uint64_t gid, hdd;
	ipmi_sunoem_fru_t fru;
	char *buf;
	ipmi_cache_entry_t *entry;

	if (nvlist_lookup_uint64(props, "gid", &gid) != 0 ||
	    nvlist_lookup_uint64(props, "hdd", &hdd) != 0) {
		return (-1);
	}

	fru.isf_type = (uint8_t)gid;
	fru.isf_id = (uint8_t)hdd;

	buf = (char *)dzmalloc(sizeof (fru.isf_data.disk.isf_capacity) + 1);

	(void) memcpy(fru.isf_data.disk.isf_manufacturer, frup->manuf,
	    MIN(sizeof (fru.isf_data.disk.isf_manufacturer),
	    sizeof (frup->manuf)));
	(void) memcpy(fru.isf_data.disk.isf_model, frup->model,
	    MIN(sizeof (fru.isf_data.disk.isf_model), sizeof (frup->model)));
	(void) memcpy(fru.isf_data.disk.isf_serial, frup->serial,
	    MIN(sizeof (fru.isf_data.disk.isf_serial), sizeof (frup->serial)));
	(void) memcpy(fru.isf_data.disk.isf_version, frup->rev,
	    MIN(sizeof (fru.isf_data.disk.isf_version), sizeof (frup->rev)));
	/*
	 * Print the size of the disk to a temporary buffer whose size is
	 * 1 more than the size of the buffer in the ipmi request data
	 * structure, so we can get the full 8 characters (instead of 7 + NUL)
	 */
	(void) snprintf(buf, sizeof (fru.isf_data.disk.isf_capacity) + 1,
	    "%.1f%s",
	    frup->size_in_bytes >= ONE_PETABYTE ?
	    (frup->size_in_bytes / ONE_PETABYTE) :
	    (frup->size_in_bytes >= ONE_TERABYTE ?
	    (frup->size_in_bytes / ONE_TERABYTE) :
	    (frup->size_in_bytes >= ONE_GIGABYTE ?
	    (frup->size_in_bytes / ONE_GIGABYTE) :
	    (frup->size_in_bytes >= ONE_MEGABYTE ?
	    (frup->size_in_bytes / ONE_MEGABYTE) :
	    (frup->size_in_bytes / ONE_KILOBYTE)))),

	    frup->size_in_bytes >= ONE_PETABYTE ? "PB" :
	    (frup->size_in_bytes >= ONE_TERABYTE ? "TB" :
	    (frup->size_in_bytes >= ONE_GIGABYTE ? "GB" :
	    (frup->size_in_bytes >= ONE_MEGABYTE ? "MB" :
	    "KB"))));
	(void) memcpy(fru.isf_data.disk.isf_capacity, buf,
	    sizeof (fru.isf_data.disk.isf_capacity));

	dfree(buf, sizeof (fru.isf_data.disk.isf_capacity) + 1);

	if (ipmi_sunoem_update_fru(g_ipmi_hdl, &fru) != 0)
		return (-1);

	/* find a cache entry or create one if necessary */
	for (entry = uu_list_first(g_ipmi_cache); entry != NULL;
	    entry = uu_list_next(g_ipmi_cache, entry)) {
		if (entry->ic_type == IPMI_CACHE_FRU &&
		    entry->ic_data.ic_fru.isf_type == gid &&
		    entry->ic_data.ic_fru.isf_id == hdd)
			break;
	}

	if (entry == NULL) {
		entry = dzmalloc(sizeof (ipmi_cache_entry_t));
		entry->ic_type = IPMI_CACHE_FRU;
		(void) uu_list_insert_before(g_ipmi_cache, NULL, entry);
	}

	(void) memcpy(&entry->ic_data.ic_fru, &fru, sizeof (fru));

	return (0);
}

static int
platform_set_sensor(nvlist_t *props)
{
	uint64_t assertmask = 0, deassertmask = 0, sid;
	boolean_t am_present, dam_present;
	ipmi_set_sensor_reading_t sr, *sp;
	ipmi_cache_entry_t *entry;
	int ret;

	/* We need at least 2 properties: `sid' and (`amask' || `dmask'): */
	am_present = nvlist_lookup_uint64(props, "amask", &assertmask) == 0;
	dam_present = nvlist_lookup_uint64(props, "dmask", &deassertmask) == 0;

	if (nvlist_lookup_uint64(props, "sid", &sid) != 0 ||
	    (!am_present && !dam_present)) {
		return (-1);
	}

	if (sid > UINT8_MAX) {
		log_warn("IPMI Plugin: Invalid sensor id `0x%llx'.\n",
		    (longlong_t)sid);
		return (-1);
	} else if (assertmask > UINT16_MAX) {
		log_warn("IPMI Plugin: Invalid assertion mask `0x%llx'.\n",
		    (longlong_t)assertmask);
		return (-1);
	} else if (assertmask > UINT16_MAX) {
		log_warn("IPMI Plugin: Invalid deassertion mask `0x%llx'.\n",
		    (longlong_t)deassertmask);
		return (-1);
	}

	(void) memset(&sr, '\0', sizeof (sr));
	sr.iss_id = (uint8_t)sid;
	if (am_present) {
		sr.iss_assert_op = IPMI_SENSOR_OP_SET;
		sr.iss_assert_state = (uint16_t)assertmask;
	}
	if (dam_present) {
		sr.iss_deassrt_op = IPMI_SENSOR_OP_SET;
		sr.iss_deassert_state = (uint16_t)deassertmask;
	}

	ret = ipmi_set_sensor_reading(g_ipmi_hdl, &sr);

	/* find a cache entry or create one if necessary */
	for (entry = uu_list_first(g_ipmi_cache); entry != NULL;
	    entry = uu_list_next(g_ipmi_cache, entry)) {
		if (entry->ic_type == IPMI_CACHE_SENSOR &&
		    entry->ic_data.ic_sensor.iss_id == (uint8_t)sid)
			break;
	}

	if (entry == NULL) {
		entry = dzmalloc(sizeof (ipmi_cache_entry_t));
		entry->ic_type = IPMI_CACHE_SENSOR;
		(void) uu_list_insert_before(g_ipmi_cache, NULL, entry);
		entry->ic_data.ic_sensor.iss_id = (uint8_t)sid;
		entry->ic_data.ic_sensor.iss_assert_op = IPMI_SENSOR_OP_SET;
		entry->ic_data.ic_sensor.iss_deassrt_op = IPMI_SENSOR_OP_SET;
	}
	sp = &entry->ic_data.ic_sensor;

	if (am_present) {
		sp->iss_assert_state |= assertmask;
		sp->iss_deassert_state &= ~assertmask;
	}
	if (dam_present) {
		sp->iss_deassert_state |= deassertmask;
		sp->iss_assert_state &= ~deassertmask;
	}

	return (ret);
}

#define	PROTOCOL_SEPARATOR ':'

static char *
extract_protocol(const char *action)
{
	char *s = strchr(action, PROTOCOL_SEPARATOR);
	char *proto = NULL;
	int len;
	int i = 0;

	/* The protocol is the string before the separator, but in lower-case */
	if (s) {
		len = (uintptr_t)s - (uintptr_t)action;
		proto = (char *)dmalloc(len + 1);
		while (i < len) {
			proto[i] = tolower(action[i]);
			i++;
		}
		proto[len] = 0;
	}

	return (proto);
}

static char *
extract_action(const char *action)
{
	/* The action is the string after the separator */
	char *s = strchr(action, PROTOCOL_SEPARATOR);

	return (s ? (s + 1) : NULL);
}

static int
do_action(const char *action, dm_fru_t *fru)
{
	nvlist_t	*props;
	char		*cmd;
	int rv = -1;
	char		*protocol = extract_protocol(action);
	char		*actionp = extract_action(action);

	if (strcmp(protocol, "ipmi") != 0) {
		log_err("unknown protocol '%s'\n", protocol);
		dstrfree(protocol);
		return (-1);
	}

	dstrfree(protocol);

	(void) pthread_mutex_lock(&g_ipmi_mtx);
	if (parse_action_string(actionp, &cmd, &props)) {
		if (strcmp(cmd, "fru") == 0) {
			rv = platform_update_fru(props, fru);
		} else if (strcmp(cmd, "state") == 0) {
			rv = platform_set_sensor(props);
		} else {
			log_err("unknown platform action '%s'\n", cmd);
		}
		dstrfree(cmd);
		nvlist_free(props);
	}
	(void) pthread_mutex_unlock(&g_ipmi_mtx);

	return (rv);
}

int
dm_platform_update_fru(const char *action, dm_fru_t *fru)
{
	return (do_action(action, fru));
}

int
dm_platform_indicator_execute(const char *action)
{
	return (do_action(action, NULL));
}

int
dm_platform_resync(void)
{
	ipmi_cache_entry_t *entry;
	int rv = 0;

	(void) pthread_mutex_lock(&g_ipmi_mtx);

	/*
	 * Called when the SP is reset, as the sensor/FRU state is not
	 * maintained across reboots.  Note that we must update the FRU
	 * information first, as certain sensor states prevent this from
	 * working.
	 */
	for (entry = uu_list_first(g_ipmi_cache); entry != NULL;
	    entry = uu_list_next(g_ipmi_cache, entry)) {
		if (entry->ic_type == IPMI_CACHE_FRU)
			rv |= ipmi_sunoem_update_fru(g_ipmi_hdl,
			    &entry->ic_data.ic_fru);
	}

	for (entry = uu_list_first(g_ipmi_cache); entry != NULL;
	    entry = uu_list_next(g_ipmi_cache, entry)) {
		if (entry->ic_type == IPMI_CACHE_SENSOR)
			rv |= ipmi_set_sensor_reading(g_ipmi_hdl,
			    &entry->ic_data.ic_sensor);
	}

	(void) pthread_mutex_unlock(&g_ipmi_mtx);
	return (rv);
}

int
dm_platform_init(void)
{
	int err;
	char *msg;

	if ((g_ipmi_hdl = ipmi_open(&err, &msg, IPMI_TRANSPORT_BMC, NULL))
	    == NULL) {
		log_warn("Failed to load libipmi: %s\n", msg);
		return (-1);
	}

	if ((g_ipmi_cache_pool = uu_list_pool_create(
	    "ipmi_cache", sizeof (ipmi_cache_entry_t),
	    offsetof(ipmi_cache_entry_t, ic_node), NULL, 0)) == NULL)
		return (-1);

	if ((g_ipmi_cache = uu_list_create(g_ipmi_cache_pool, NULL, 0))
	    == NULL)
		return (-1);

	return (0);
}

void
dm_platform_fini(void)
{
	if (g_ipmi_hdl)
		ipmi_close(g_ipmi_hdl);
	if (g_ipmi_cache) {
		ipmi_cache_entry_t *entry;

		while ((entry = uu_list_first(g_ipmi_cache)) != NULL) {
			uu_list_remove(g_ipmi_cache, entry);
			dfree(entry, sizeof (*entry));
		}
		uu_list_destroy(g_ipmi_cache);
	}
	if (g_ipmi_cache_pool)
		uu_list_pool_destroy(g_ipmi_cache_pool);
}
