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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */


/*
 * Config routines common to idmap(1M) and idmapd(1M)
 */

#include <stdlib.h>
#include <strings.h>
#include <libintl.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include <port.h>
#include <sys/socket.h>
#include <net/route.h>
#include <sys/u8_textprep.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <note.h>
#include "idmapd.h"
#include "addisc.h"

#define	MACHINE_SID_LEN		(9 + 3 * 11)
#define	FMRI_BASE		"svc:/system/idmap"
#define	CONFIG_PG		"config"
#define	DEBUG_PG		"debug"
#define	RECONFIGURE		1
#define	POKE_AUTO_DISCOVERY	2
#define	KICK_AUTO_DISCOVERY	3

/*
 * Default cache timeouts.  Can override via svccfg
 * config/id_cache_timeout = count: seconds
 * config/name_cache_timeout = count: seconds
 */
#define	ID_CACHE_TMO_DEFAULT	86400
#define	NAME_CACHE_TMO_DEFAULT	604800

/*
 * Default maximum time between rediscovery runs.
 * config/rediscovery_interval = count: seconds
 */
#define	REDISCOVERY_INTERVAL_DEFAULT	3600

/*
 * Mininum time between rediscovery runs, in case adutils gives us a
 * really short TTL (which it never should, but be defensive)
 * (not configurable) seconds.
 */
#define	MIN_REDISCOVERY_INTERVAL	60

enum event_type {
	EVENT_NOTHING,	/* Woke up for no good reason */
	EVENT_TIMEOUT,	/* Timeout expired */
	EVENT_ROUTING,	/* An interesting routing event happened */
	EVENT_POKED,	/* Requested from degrade_svc() */
	EVENT_KICKED,	/* Force rediscovery, i.e. DC failed. */
	EVENT_REFRESH,	/* SMF refresh */
};


static void idmapd_set_krb5_realm(char *);

static pthread_t update_thread_handle = 0;

static int idmapd_ev_port = -1;
static int rt_sock = -1;

struct enum_lookup_map directory_mapping_map[] = {
	{ DIRECTORY_MAPPING_NONE, "none" },
	{ DIRECTORY_MAPPING_NAME, "name" },
	{ DIRECTORY_MAPPING_IDMU, "idmu" },
	{ 0, NULL },
};

struct enum_lookup_map trust_dir_map[] = {
	{ 1, "they trust us" },
	{ 2, "we trust them" },
	{ 3, "we trust each other" },
	{ 0, NULL },
};

static int
generate_machine_uuid(char **machine_uuid)
{
	uuid_t uu;

	*machine_uuid = calloc(1, UUID_PRINTABLE_STRING_LENGTH + 1);
	if (*machine_uuid == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (-1);
	}

	uuid_clear(uu);
	uuid_generate_time(uu);
	uuid_unparse(uu, *machine_uuid);

	return (0);
}

static int
generate_machine_sid(char **machine_sid, char *machine_uuid)
{
	union {
		uuid_t uu;
		uint32_t v[4];
	} uv;
	int len;

	/*
	 * Split the 128-bit machine UUID into three 32-bit values
	 * we'll use as the "sub-authorities" of the machine SID.
	 * The machine_sid will have the form S-1-5-21-J-K-L
	 * (that's four sub-authorities altogether) where:
	 *	J = last 4 bytes of node_addr,
	 *	K = time_mid, time_hi_and_version
	 *	L = time_low
	 * (see struct uuid)
	 */

	(void) memset(&uv, 0, sizeof (uv));
	(void) uuid_parse(machine_uuid, uv.uu);

	len = asprintf(machine_sid, "S-1-5-21-%u-%u-%u",
	    uv.v[3], uv.v[0], uv.v[1]);

	if (len == -1 || *machine_sid == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (-1);
	}

	return (0);
}


/* In the case of error, exists is set to FALSE anyway */
static int
prop_exists(idmap_cfg_handles_t *handles, const char *name, boolean_t *exists)
{

	scf_property_t *scf_prop;

	*exists = B_FALSE;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) == 0)
		*exists = B_TRUE;

	scf_property_destroy(scf_prop);

	return (0);
}

static int
get_debug(idmap_cfg_handles_t *handles, const char *name)
{
	int64_t i64 = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		abort();
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		abort();
	}

	if (scf_pg_get_property(handles->debug_pg, name, scf_prop) < 0) {
		/* this is OK: the property is just undefined */
		goto destruction;
	}


	if (scf_property_get_value(scf_prop, value) < 0) {
		/* It is still OK when a property doesn't have any value */
		goto destruction;
	}

	if (scf_value_get_integer(value, &i64) != 0) {
		idmapdlog(LOG_ERR, "Can not retrieve %s/%s:  %s",
		    DEBUG_PG, name, scf_strerror(scf_error()));
		abort();
	}

destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return ((int)i64);
}

static int
get_val_bool(idmap_cfg_handles_t *handles, const char *name,
	boolean_t *val, boolean_t default_val)
{
	int rc = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	*val = default_val;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	/* It is OK if the property is undefined */
	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
		goto destruction;


	/* It is still OK when a property doesn't have any value */
	if (scf_property_get_value(scf_prop, value) < 0)
		goto destruction;

	uint8_t b;
	rc = scf_value_get_boolean(value, &b);

	if (rc == 0)
		*val = (boolean_t)b;

destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return (rc);
}

static int
get_val_int(idmap_cfg_handles_t *handles, const char *name,
	void *val, scf_type_t type)
{
	int rc = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	switch (type) {
	case SCF_TYPE_COUNT:
		*(uint64_t *)val = 0;
		break;
	case SCF_TYPE_INTEGER:
		*(int64_t *)val = 0;
		break;
	default:
		idmapdlog(LOG_ERR, "Invalid scf integer type (%d)",
		    type);
		abort();
	}

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
	/* this is OK: the property is just undefined */
		goto destruction;


	if (scf_property_get_value(scf_prop, value) < 0)
	/* It is still OK when a property doesn't have any value */
		goto destruction;

	switch (type) {
	case SCF_TYPE_COUNT:
		rc = scf_value_get_count(value, val);
		break;
	case SCF_TYPE_INTEGER:
		rc = scf_value_get_integer(value, val);
		break;
	default:
		abort();	/* tested above */
		/* NOTREACHED */
	}

	if (rc != 0) {
		idmapdlog(LOG_ERR, "Can not retrieve config/%s:  %s",
		    name, scf_strerror(scf_error()));
	}

destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return (rc);
}

static char *
scf_value2string(const char *name, scf_value_t *value)
{
	static size_t max_val = 0;

	if (max_val == 0)
		max_val = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	char buf[max_val + 1];
	if (scf_value_get_astring(value, buf, max_val + 1) < 0) {
		idmapdlog(LOG_ERR, "Can not retrieve config/%s:  %s",
		    name, scf_strerror(scf_error()));
		return (NULL);
	}

	char *s = strdup(buf);
	if (s == NULL)
		idmapdlog(LOG_ERR, "Out of memory");

	return (s);
}

static int
get_val_ds(idmap_cfg_handles_t *handles, const char *name, int defport,
		ad_disc_ds_t **val)
{
	char port_str[8];
	struct addrinfo hints;
	struct addrinfo *ai;
	ad_disc_ds_t *servers = NULL;
	scf_property_t *scf_prop;
	scf_value_t *value;
	scf_iter_t *iter;
	char *host, *portstr;
	int err, len, i;
	int count = 0;
	int rc = -1;

	*val = NULL;

restart:
	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}

	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	iter = scf_iter_create(handles->main);
	if (iter == NULL) {
		idmapdlog(LOG_ERR, "scf_iter_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_value_destroy(value);
		scf_property_destroy(scf_prop);
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0) {
		/* this is OK: the property is just undefined */
		rc = 0;
		goto destruction;
	}

	if (scf_iter_property_values(iter, scf_prop) < 0) {
		idmapdlog(LOG_ERR,
		    "scf_iter_property_values(%s) failed: %s",
		    name, scf_strerror(scf_error()));
		goto destruction;
	}

	/* Workaround scf bugs -- can't reset an iteration */
	if (count == 0) {
		while (scf_iter_next_value(iter, value) > 0)
			count++;

		if (count == 0) {
			/* no values */
			rc = 0;
			goto destruction;
		}

		scf_value_destroy(value);
		scf_iter_destroy(iter);
		scf_property_destroy(scf_prop);
		goto restart;
	}

	if ((servers = calloc(count + 1, sizeof (*servers))) == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		goto destruction;
	}

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	host = NULL;

	i = 0;
	while (i < count && scf_iter_next_value(iter, value) > 0) {
		if (host) {
			free(host);
			host = NULL;
		}
		servers[i].priority = 0;
		servers[i].weight = 100;
		servers[i].port = defport;
		if ((host = scf_value2string(name, value)) == NULL)
			continue;
		if ((portstr = strchr(host, ':')) != NULL) {
			*portstr++ = '\0';
			servers[i].port = strtol(portstr,
			    (char **)NULL, 10);
			if (servers[i].port == 0)
				servers[i].port = defport;
		}

		/*
		 * Ignore this server if the hostname is too long
		 * or empty (continue without i++)
		 */
		len = strlen(host);
		if (len == 0) {
			if (DBG(CONFIG, 1)) {
				idmapdlog(LOG_INFO, "%s host=\"\"", name);
			}
			continue;
		}
		if (len >= sizeof (servers->host)) {
			idmapdlog(LOG_ERR, "Host name too long: %s", host);
			idmapdlog(LOG_ERR, "ignoring %s value", name);
			continue;
		}

		/*
		 * Get the host address too.  If we can't, then
		 * log an error and skip this host.
		 */
		(void) snprintf(port_str, sizeof (port_str),
		    "%d", servers[i].port);
		ai = NULL;
		err = getaddrinfo(host, port_str, &hints, &ai);
		if (err != 0) {
			idmapdlog(LOG_ERR, "No address for host: %s (%s)",
			    host, gai_strerror(err));
			idmapdlog(LOG_ERR, "ignoring %s value", name);
			continue;
		}

		(void) strlcpy(servers[i].host, host,
		    sizeof (servers->host));
		(void) memcpy(&servers[i].addr, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);

		/* Added a DS to the array. */
		i++;
	}
	free(host);

	if (i == 0) {
		if (DBG(CONFIG, 1)) {
			idmapdlog(LOG_INFO, "%s is empty", name);
		}
		free(servers);
		servers = NULL;
	}
	*val = servers;

	rc = 0;

destruction:
	scf_value_destroy(value);
	scf_iter_destroy(iter);
	scf_property_destroy(scf_prop);

	if (rc < 0) {
		if (servers)
			free(servers);
		*val = NULL;
	}

	return (rc);
}

static int
get_val_astring(idmap_cfg_handles_t *handles, const char *name, char **val)
{
	int rc = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	*val = NULL;

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
	/* this is OK: the property is just undefined */
		goto destruction;

	if (scf_property_get_value(scf_prop, value) < 0) {
		idmapdlog(LOG_ERR,
		    "scf_property_get_value(%s) failed: %s",
		    name, scf_strerror(scf_error()));
		rc = -1;
		goto destruction;
	}

	*val = scf_value2string(name, value);
	if (*val == NULL)
		rc = -1;

destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	if (rc < 0) {
		if (*val)
			free(*val);
		*val = NULL;
	}

	return (rc);
}


static int
del_val(
    idmap_cfg_handles_t *handles,
    scf_propertygroup_t *pg,
    const char *name)
{
	int			rc = -1;
	int			ret;
	scf_transaction_t	*tx = NULL;
	scf_transaction_entry_t	*ent = NULL;

	if ((tx = scf_transaction_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR,
		    "scf_transaction_create() failed: %s",
		    scf_strerror(scf_error()));
		goto destruction;
	}
	if ((ent = scf_entry_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR,
		    "scf_entry_create() failed: %s",
		    scf_strerror(scf_error()));
		goto destruction;
	}

	do {
		if (scf_pg_update(pg) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_pg_update(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}
		if (scf_transaction_start(tx, pg) != 0) {
			idmapdlog(LOG_ERR,
			    "scf_transaction_start(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_transaction_property_delete(tx, ent, name) != 0) {
			/* Don't complain if it already doesn't exist. */
			if (scf_error() != SCF_ERROR_NOT_FOUND) {
				idmapdlog(LOG_ERR,
				    "scf_transaction_property_delete() failed:"
				    " %s",
				    scf_strerror(scf_error()));
			}
			goto destruction;
		}

		ret = scf_transaction_commit(tx);

		if (ret == 0)
			scf_transaction_reset(tx);
	} while (ret == 0);

	if (ret == -1) {
		idmapdlog(LOG_ERR,
		    "scf_transaction_commit(%s) failed: %s",
		    name, scf_strerror(scf_error()));
		goto destruction;
	}

	rc = 0;

destruction:
	if (ent != NULL)
		scf_entry_destroy(ent);
	if (tx != NULL)
		scf_transaction_destroy(tx);
	return (rc);
}


static int
set_val(
    idmap_cfg_handles_t *handles,
    scf_propertygroup_t *pg,
    const char *name,
    scf_value_t *value)
{
	int			rc = -1;
	int			i;
	scf_property_t		*prop = NULL;
	scf_transaction_t	*tx = NULL;
	scf_transaction_entry_t	*ent = NULL;

	if ((prop = scf_property_create(handles->main)) == NULL ||
	    (tx = scf_transaction_create(handles->main)) == NULL ||
	    (ent = scf_entry_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR, "Unable to set property %s",
		    name, scf_strerror(scf_error()));
		goto destruction;
	}

	for (i = 0; i < MAX_TRIES; i++) {
		int ret;

		if (scf_pg_update(pg) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_pg_update() failed: %s",
			    scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_transaction_start(tx, pg) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_transaction_start(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}

		ret = scf_pg_get_property(pg, name, prop);
		if (ret == SCF_SUCCESS) {
			if (scf_transaction_property_change_type(tx, ent, name,
			    scf_value_type(value)) < 0) {
				idmapdlog(LOG_ERR,
				    "scf_transaction_property_change_type(%s)"
				    " failed: %s",
				    name, scf_strerror(scf_error()));
				goto destruction;
			}
		} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
			if (scf_transaction_property_new(tx, ent, name,
			    scf_value_type(value)) < 0) {
				idmapdlog(LOG_ERR,
				    "scf_transaction_property_new() failed: %s",
				    scf_strerror(scf_error()));
				goto destruction;
			}
		} else {
			idmapdlog(LOG_ERR,
			    "scf_pg_get_property(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_entry_add_value(ent, value) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_entry_add_value() failed: %s",
			    scf_strerror(scf_error()));
			goto destruction;
		}

		ret = scf_transaction_commit(tx);
		if (ret == 0) {
			/*
			 * Property group set in scf_transaction_start()
			 * is not the most recent. Update pg, reset tx and
			 * retry tx.
			 */
			idmapdlog(LOG_WARNING,
			    "scf_transaction_commit(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			scf_transaction_reset(tx);
			continue;
		}
		if (ret != 1) {
			idmapdlog(LOG_ERR,
			    "scf_transaction_commit(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}
		/* Success! */
		rc = 0;
		break;
	}

destruction:
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(prop);
	return (rc);
}

static int
set_val_integer(
    idmap_cfg_handles_t *handles,
    scf_propertygroup_t *pg,
    const char *name,
    int64_t val)
{
	scf_value_t		*value = NULL;
	int			rc;

	if ((value = scf_value_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR, "Unable to set property %s",
		    name, scf_strerror(scf_error()));
		return (-1);
	}

	scf_value_set_integer(value, val);

	rc = set_val(handles, pg, name, value);

	scf_value_destroy(value);

	return (rc);
}


static int
set_val_astring(
    idmap_cfg_handles_t *handles,
    scf_propertygroup_t *pg,
    const char *name,
    const char *val)
{
	scf_value_t		*value = NULL;
	int			rc = -1;

	if ((value = scf_value_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR, "Unable to set property %s",
		    name, scf_strerror(scf_error()));
		goto out;
	}

	if (scf_value_set_astring(value, val) == -1) {
		idmapdlog(LOG_ERR,
		    "scf_value_set_astring() failed: %s",
		    scf_strerror(scf_error()));
		goto out;
	}

	rc = set_val(handles, pg, name, value);

out:
	scf_value_destroy(value);
	return (rc);
}



/*
 * This function updates a boolean value.
 * If nothing has changed it returns 0 else 1
 */
static int
update_bool(boolean_t *value, boolean_t *new, char *name)
{
	if (*value == *new)
		return (0);

	if (DBG(CONFIG, 1)) {
		idmapdlog(LOG_INFO, "change %s=%s", name,
		    *new ? "true" : "false");
	}

	*value = *new;
	return (1);
}

/*
 * This function updates a uint64_t value.
 * If nothing has changed it returns 0 else 1
 */
static int
update_uint64(uint64_t *value, uint64_t *new, char *name)
{
	if (*value == *new)
		return (0);

	if (DBG(CONFIG, 1))
		idmapdlog(LOG_INFO, "change %s=%llu", name, *new);

	*value = *new;
	return (1);
}

/*
 * This function updates a string value.
 * If nothing has changed it returns 0 else 1
 */
static int
update_string(char **value, char **new, char *name)
{
	int changed;

	if (*new == NULL && *value != NULL)
		changed = 1;
	else if (*new != NULL && *value == NULL)
		changed = 1;
	else if (*new != NULL && *value != NULL && strcmp(*new, *value) != 0)
		changed = 1;
	else
		changed = 0;

	/*
	 * Note that even if unchanged we can't just return; we must free one
	 * of the values.
	 */

	if (DBG(CONFIG, 1) && changed)
		idmapdlog(LOG_INFO, "change %s=%s", name, CHECK_NULL(*new));

	free(*value);
	*value = *new;
	*new = NULL;
	return (changed);
}

static int
update_enum(int *value, int *new, char *name, struct enum_lookup_map *map)
{
	if (*value == *new)
		return (0);

	if (DBG(CONFIG, 1)) {
		idmapdlog(LOG_INFO, "change %s=%s", name,
		    enum_lookup(*new, map));
	}

	*value = *new;

	return (1);
}

/*
 * This function updates a directory service structure.
 * If nothing has changed it returns 0 else 1
 */
static int
update_dirs(ad_disc_ds_t **value, ad_disc_ds_t **new, char *name)
{

	if (*value == *new)
		/* Nothing to do */
		return (0);

	if (*value != NULL && *new != NULL &&
	    ad_disc_compare_ds(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	if (*value != NULL)
		free(*value);

	*value = *new;
	*new = NULL;

	if (*value == NULL) {
		/* We're unsetting this DS property */
		if (DBG(CONFIG, 1))
			idmapdlog(LOG_INFO, "change %s=<none>", name);
		return (1);
	}

	if (DBG(CONFIG, 1)) {
		/* List all the new DSs */
		char buf[64];
		ad_disc_ds_t *ds;
		for (ds = *value; ds->host[0] != '\0'; ds++) {
			if (ad_disc_getnameinfo(buf, sizeof (buf), &ds->addr))
				(void) strlcpy(buf, "?", sizeof (buf));
			idmapdlog(LOG_INFO, "change %s=%s addr=%s port=%d",
			    name, ds->host, buf, ds->port);
		}
	}
	return (1);
}

/*
 * This function updates a trusted domains structure.
 * If nothing has changed it returns 0 else 1
 */
static int
update_trusted_domains(ad_disc_trusteddomains_t **value,
			ad_disc_trusteddomains_t **new, char *name)
{
	int i;

	if (*value == *new)
		/* Nothing to do */
		return (0);

	if (*value != NULL && *new != NULL &&
	    ad_disc_compare_trusteddomains(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	if (*value != NULL)
		free(*value);

	*value = *new;
	*new = NULL;

	if (*value == NULL) {
		/* We're unsetting this DS property */
		if (DBG(CONFIG, 1))
			idmapdlog(LOG_INFO, "change %s=<none>", name);
		return (1);
	}

	if (DBG(CONFIG, 1)) {
		/* List all the new domains */
		for (i = 0; (*value)[i].domain[0] != '\0'; i++) {
			idmapdlog(LOG_INFO, "change %s=%s direction=%s", name,
			    (*value)[i].domain,
			    enum_lookup((*value)[i].direction, trust_dir_map));
		}
	}
	return (1);
}


/*
 * This function updates a domains in a forest structure.
 * If nothing has changed it returns 0 else 1
 */
static int
update_domains_in_forest(ad_disc_domainsinforest_t **value,
			ad_disc_domainsinforest_t **new, char *name)
{
	int i;

	if (*value == *new)
		/* Nothing to do */
		return (0);

	if (*value != NULL && *new != NULL &&
	    ad_disc_compare_domainsinforest(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	if (*value != NULL)
		free(*value);

	*value = *new;
	*new = NULL;

	if (*value == NULL) {
		/* We're unsetting this DS property */
		if (DBG(CONFIG, 1))
			idmapdlog(LOG_INFO, "change %s=<none>", name);
		return (1);
	}

	if (DBG(CONFIG, 1)) {
		/* List all the new domains */
		for (i = 0; (*value)[i].domain[0] != '\0'; i++) {
			idmapdlog(LOG_INFO, "change %s=%s", name,
			    (*value)[i].domain);
		}
	}
	return (1);
}


static void
free_trusted_forests(idmap_trustedforest_t **value, int *num_values)
{
	int i;

	for (i = 0; i < *num_values; i++) {
		free((*value)[i].forest_name);
		free((*value)[i].global_catalog);
		free((*value)[i].domains_in_forest);
	}
	free(*value);
	*value = NULL;
	*num_values = 0;
}


static int
compare_trusteddomainsinforest(ad_disc_domainsinforest_t *df1,
			ad_disc_domainsinforest_t *df2)
{
	int		i, j;
	int		num_df1 = 0;
	int		num_df2 = 0;
	boolean_t	match;

	for (i = 0; df1[i].domain[0] != '\0'; i++)
		if (df1[i].trusted)
			num_df1++;

	for (j = 0; df2[j].domain[0] != '\0'; j++)
		if (df2[j].trusted)
			num_df2++;

	if (num_df1 != num_df2)
		return (1);

	for (i = 0; df1[i].domain[0] != '\0'; i++) {
		if (df1[i].trusted) {
			match = B_FALSE;
			for (j = 0; df2[j].domain[0] != '\0'; j++) {
				if (df2[j].trusted &&
				    domain_eq(df1[i].domain, df2[j].domain) &&
				    strcmp(df1[i].sid, df2[j].sid) == 0) {
					match = B_TRUE;
					break;
				}
			}
			if (!match)
				return (1);
		}
	}
	return (0);
}



/*
 * This function updates trusted forest structure.
 * If nothing has changed it returns 0 else 1
 */
static int
update_trusted_forest(idmap_trustedforest_t **value, int *num_value,
			idmap_trustedforest_t **new, int *num_new, char *name)
{
	int i, j;
	boolean_t match;

	if (*value == *new)
		/* Nothing to do */
		return (0);

	if (*value != NULL && *new != NULL) {
		if (*num_value != *num_new)
			goto not_equal;
		for (i = 0; i < *num_value; i++) {
			match = B_FALSE;
			for (j = 0; j < *num_new; j++) {
				if (strcmp((*value)[i].forest_name,
				    (*new)[j].forest_name) == 0 &&
				    ad_disc_compare_ds(
				    (*value)[i].global_catalog,
				    (*new)[j].global_catalog) == 0 &&
				    compare_trusteddomainsinforest(
				    (*value)[i].domains_in_forest,
				    (*new)[j].domains_in_forest) == 0) {
					match = B_TRUE;
					break;
				}
			}
			if (!match)
				goto not_equal;
		}
		free_trusted_forests(new, num_new);
		return (0);
	}
not_equal:
	if (*value != NULL)
		free_trusted_forests(value, num_value);
	*value = *new;
	*num_value = *num_new;
	*new = NULL;
	*num_new = 0;

	if (*value == NULL) {
		/* We're unsetting this DS property */
		if (DBG(CONFIG, 1))
			idmapdlog(LOG_INFO, "change %s=<none>", name);
		return (1);
	}

	if (DBG(CONFIG, 1)) {
		/* List all the trusted forests */
		for (i = 0; i < *num_value; i++) {
			idmap_trustedforest_t *f = &(*value)[i];
			for (j = 0;
			    f->domains_in_forest[j].domain[0] != '\0';
			    j++) {
				/* List trusted Domains in the forest. */
				if (f->domains_in_forest[j].trusted)
					idmapdlog(LOG_INFO,
					    "change %s=%s domain=%s",
					    name, f->forest_name,
					    f->domains_in_forest[j].domain);
			}
			/* List the hosts */
			for (j = 0;
			    f->global_catalog[j].host[0] != '\0';
			    j++) {
				idmapdlog(LOG_INFO,
				    "change %s=%s host=%s port=%d",
				    name, f->forest_name,
				    f->global_catalog[j].host,
				    f->global_catalog[j].port);
			}
		}
	}
	return (1);
}

const char *
enum_lookup(int value, struct enum_lookup_map *map)
{
	for (; map->string != NULL; map++) {
		if (value == map->value) {
			return (map->string);
		}
	}
	return ("(invalid)");
}

/*
 * Returns 1 if the PF_ROUTE socket event indicates that we should rescan the
 * interfaces.
 *
 * Shamelessly based on smb_nics_changed() and other PF_ROUTE uses in ON.
 */
static
boolean_t
pfroute_event_is_interesting(int rt_sock)
{
	int nbytes;
	int64_t msg[2048 / 8];
	struct rt_msghdr *rtm;
	boolean_t is_interesting = B_FALSE;

	for (;;) {
		if ((nbytes = read(rt_sock, msg, sizeof (msg))) <= 0)
			break;
		rtm = (struct rt_msghdr *)msg;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (nbytes < rtm->rtm_msglen)
			continue;
		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_IFINFO:
			is_interesting = B_TRUE;
			break;
		default:
			break;
		}
	}
	return (is_interesting);
}

/*
 * Wait for an event, and report what kind of event occurred.
 *
 * Note that there are cases where we are awoken but don't care about
 * the lower-level event.  We can't just loop here because we can't
 * readily calculate how long to sleep the next time.  We return
 * EVENT_NOTHING and let the caller loop.
 */
static
enum event_type
wait_for_event(struct timespec *timeoutp)
{
	port_event_t pe;

	(void) memset(&pe, 0, sizeof (pe));
	if (port_get(idmapd_ev_port, &pe, timeoutp) != 0) {
		switch (errno) {
		case EINTR:
			return (EVENT_NOTHING);
		case ETIME:
			/* Timeout */
			return (EVENT_TIMEOUT);
		default:
			/* EBADF, EBADFD, EFAULT, EINVAL (end of time?)? */
			idmapdlog(LOG_ERR, "Event port failed: %s",
			    strerror(errno));
			exit(1);
			/* NOTREACHED */
		}
	}


	switch (pe.portev_source) {
	case 0:
		/*
		 * This isn't documented, but seems to be what you get if
		 * the timeout is zero seconds and there are no events
		 * pending.
		 */
		return (EVENT_TIMEOUT);

	case PORT_SOURCE_USER:
		switch (pe.portev_events) {
		case RECONFIGURE:
			return (EVENT_REFRESH);
		case POKE_AUTO_DISCOVERY:
			return (EVENT_POKED);
		case KICK_AUTO_DISCOVERY:
			return (EVENT_KICKED);
		}
		return (EVENT_NOTHING);

	case PORT_SOURCE_FD:
		if (pe.portev_object == rt_sock) {
			/*
			 * PF_ROUTE socket read event:
			 *    re-associate fd
			 *    handle event
			 */
			if (port_associate(idmapd_ev_port, PORT_SOURCE_FD,
			    rt_sock, POLLIN, NULL) != 0) {
				idmapdlog(LOG_ERR, "Failed to re-associate the "
				    "routing socket with the event port: %s",
				    strerror(errno));
				abort();
			}
			/*
			 * The network configuration may still be in flux.
			 * No matter, the resolver will re-transmit and
			 * timeout if need be.
			 */
			if (pfroute_event_is_interesting(rt_sock)) {
				if (DBG(CONFIG, 1)) {
					idmapdlog(LOG_DEBUG,
					    "Interesting routing event");
				}
				return (EVENT_ROUTING);
			} else {
				if (DBG(CONFIG, 2)) {
					idmapdlog(LOG_DEBUG,
					    "Boring routing event");
				}
				return (EVENT_NOTHING);
			}
		}
		/* Event on an FD other than the routing FD? Ignore it. */
		break;
	}

	return (EVENT_NOTHING);
}

void *
idmap_cfg_update_thread(void *arg)
{
	NOTE(ARGUNUSED(arg))
	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;
	const ad_disc_t		ad_ctx = _idmapdstate.cfg->handles.ad_ctx;
	int flags = CFG_DISCOVER;

	for (;;) {
		struct timespec timeout;
		struct timespec	*timeoutp;
		int		rc;
		int		ttl, max_ttl;

		(void) ad_disc_SubnetChanged(ad_ctx);

		rc = idmap_cfg_load(_idmapdstate.cfg, flags);
		if (rc < -1) {
			idmapdlog(LOG_ERR, "Fatal errors while reading "
			    "SMF properties");
			exit(1);
		} else if (rc == -1) {
			idmapdlog(LOG_WARNING,
			    "Errors re-loading configuration may cause AD "
			    "lookups to fail");
		}

		/*
		 * Wait for an interesting event.  Note that we might get
		 * boring events between interesting events.  If so, we loop.
		 */
		flags = CFG_DISCOVER;
		for (;;) {
			/*
			 * If we don't know our domain name, don't bother
			 * with rediscovery until the next config change.
			 * Avoids hourly noise in workgroup mode.
			 */
			if (pgcfg->domain_name == NULL)
				ttl = -1;
			else
				ttl = ad_disc_get_TTL(ad_ctx);
			if (ttl < 0) {
				timeoutp = NULL;
			} else {
				max_ttl = (int)pgcfg->rediscovery_interval;
				if (ttl > max_ttl)
					ttl = max_ttl;
				if (ttl < MIN_REDISCOVERY_INTERVAL)
					ttl = MIN_REDISCOVERY_INTERVAL;
				timeout.tv_sec = ttl;
				timeout.tv_nsec = 0;
				timeoutp = &timeout;
			}

			if (DBG(CONFIG, 1))
				idmapdlog(LOG_DEBUG,
				    "_cfg_update_thread waiting");

			switch (wait_for_event(timeoutp)) {
			case EVENT_NOTHING:
				if (DBG(CONFIG, 2))
					idmapdlog(LOG_DEBUG, "Boring event.");
				continue;
			case EVENT_REFRESH:
				if (DBG(CONFIG, 1))
					idmapdlog(LOG_INFO, "SMF refresh");
				/*
				 * Forget any DC we had previously.
				 */
				flags |= CFG_FORGET_DC;

				/*
				 * Blow away the ccache, we might have
				 * re-joined the domain or joined a new one
				 */
				(void) unlink(IDMAP_CACHEDIR "/ccache");
				break;
			case EVENT_POKED:
				if (DBG(CONFIG, 1))
					idmapdlog(LOG_DEBUG, "poked");
				break;
			case EVENT_KICKED:
				if (DBG(CONFIG, 1))
					idmapdlog(LOG_DEBUG, "kicked");
				flags |= CFG_FORGET_DC;
				break;
			case EVENT_TIMEOUT:
				if (DBG(CONFIG, 1))
					idmapdlog(LOG_DEBUG, "TTL expired");
				break;
			case EVENT_ROUTING:
				/* Already logged to DEBUG */
				break;
			}
			/* An interesting event! */
			break;
		}
	}
	/*
	 * Lint isn't happy with the concept of a function declared to
	 * return something, that doesn't return.  Of course, merely adding
	 * the return isn't enough, because it's never reached...
	 */
	/*NOTREACHED*/
	return (NULL);
}

int
idmap_cfg_start_updates(void)
{
	if ((idmapd_ev_port = port_create()) < 0) {
		idmapdlog(LOG_ERR, "Failed to create event port: %s",
		    strerror(errno));
		return (-1);
	}

	if ((rt_sock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		idmapdlog(LOG_ERR, "Failed to open routing socket: %s",
		    strerror(errno));
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if (fcntl(rt_sock, F_SETFL, O_NDELAY|O_NONBLOCK) < 0) {
		idmapdlog(LOG_ERR, "Failed to set routing socket flags: %s",
		    strerror(errno));
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if (port_associate(idmapd_ev_port, PORT_SOURCE_FD,
	    rt_sock, POLLIN, NULL) != 0) {
		idmapdlog(LOG_ERR, "Failed to associate the routing "
		    "socket with the event port: %s", strerror(errno));
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if ((errno = pthread_create(&update_thread_handle, NULL,
	    idmap_cfg_update_thread, NULL)) != 0) {
		idmapdlog(LOG_ERR, "Failed to start update thread: %s",
		    strerror(errno));
		(void) port_dissociate(idmapd_ev_port, PORT_SOURCE_FD, rt_sock);
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	return (0);
}

/*
 * Reject attribute names with invalid characters.
 */
static
int
valid_ldap_attr(const char *attr) {
	for (; *attr; attr++) {
		if (!isalnum(*attr) && *attr != '-' &&
		    *attr != '_' && *attr != '.' && *attr != ';')
			return (0);
	}
	return (1);
}

static
void
idmapd_set_debug(
    idmap_cfg_handles_t *handles,
    enum idmapd_debug item,
    const char *name)
{
	int val;

	if (item < 0 || item > IDMAPD_DEBUG_MAX)
		return;

	val = get_debug(handles, name);

	if (val != _idmapdstate.debug[item])
		idmapdlog(LOG_DEBUG, "%s/%s = %d", DEBUG_PG, name, val);

	_idmapdstate.debug[item] = val;
}

static
void
check_smf_debug_mode(idmap_cfg_handles_t *handles)
{
	idmapd_set_debug(handles, IDMAPD_DEBUG_ALL, "all");
	idmapd_set_debug(handles, IDMAPD_DEBUG_CONFIG, "config");
	idmapd_set_debug(handles, IDMAPD_DEBUG_MAPPING, "mapping");
	idmapd_set_debug(handles, IDMAPD_DEBUG_DISC, "discovery");
	idmapd_set_debug(handles, IDMAPD_DEBUG_DNS, "dns");
	idmapd_set_debug(handles, IDMAPD_DEBUG_LDAP, "ldap");

	adutils_set_debug(AD_DEBUG_ALL, _idmapdstate.debug[IDMAPD_DEBUG_ALL]);
	adutils_set_debug(AD_DEBUG_DISC, _idmapdstate.debug[IDMAPD_DEBUG_DISC]);
	adutils_set_debug(AD_DEBUG_DNS, _idmapdstate.debug[IDMAPD_DEBUG_DNS]);
	adutils_set_debug(AD_DEBUG_LDAP, _idmapdstate.debug[IDMAPD_DEBUG_LDAP]);
}

/*
 * This is the half of idmap_cfg_load() that loads property values from
 * SMF (using the config/ property group of the idmap FMRI).
 *
 * Return values: 0 -> success, -1 -> failure, -2 -> hard failures
 *               -3 -> hard smf config failures
 * reading from SMF.
 */
static int
idmap_cfg_load_smf(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg,
	int * const errors)
{
	int rc;
	char *s;

	*errors = 0;

	if (scf_pg_update(handles->config_pg) < 0) {
		idmapdlog(LOG_ERR, "scf_pg_update() failed: %s",
		    scf_strerror(scf_error()));
		return (-2);
	}

	if (scf_pg_update(handles->debug_pg) < 0) {
		idmapdlog(LOG_ERR, "scf_pg_update() failed: %s",
		    scf_strerror(scf_error()));
		return (-2);
	}

	check_smf_debug_mode(handles);

	rc = get_val_bool(handles, "unresolvable_sid_mapping",
	    &pgcfg->eph_map_unres_sids, B_TRUE);
	if (rc != 0)
		(*errors)++;

	rc = get_val_bool(handles, "use_ads",
	    &pgcfg->use_ads, B_TRUE);
	if (rc != 0)
		(*errors)++;

	rc = get_val_bool(handles, "use_lsa",
	    &pgcfg->use_lsa, B_TRUE);
	if (rc != 0)
		(*errors)++;

	rc = get_val_bool(handles, "disable_cross_forest_trusts",
	    &pgcfg->disable_cross_forest_trusts, B_TRUE);
	if (rc != 0)
		(*errors)++;

	rc = get_val_astring(handles, "directory_based_mapping", &s);
	if (rc != 0)
		(*errors)++;
	else if (s == NULL || strcasecmp(s, "none") == 0)
		pgcfg->directory_based_mapping = DIRECTORY_MAPPING_NONE;
	else if (strcasecmp(s, "name") == 0)
		pgcfg->directory_based_mapping = DIRECTORY_MAPPING_NAME;
	else if (strcasecmp(s, "idmu") == 0)
		pgcfg->directory_based_mapping = DIRECTORY_MAPPING_IDMU;
	else {
		pgcfg->directory_based_mapping = DIRECTORY_MAPPING_NONE;
		idmapdlog(LOG_ERR,
		"config/directory_based_mapping:  invalid value \"%s\" ignored",
		    s);
		(*errors)++;
	}
	free(s);

	rc = get_val_int(handles, "list_size_limit",
	    &pgcfg->list_size_limit, SCF_TYPE_COUNT);
	if (rc != 0)
		(*errors)++;

	rc = get_val_int(handles, "id_cache_timeout",
	    &pgcfg->id_cache_timeout, SCF_TYPE_COUNT);
	if (rc != 0)
		(*errors)++;
	if (pgcfg->id_cache_timeout == 0)
		pgcfg->id_cache_timeout = ID_CACHE_TMO_DEFAULT;

	rc = get_val_int(handles, "name_cache_timeout",
	    &pgcfg->name_cache_timeout, SCF_TYPE_COUNT);
	if (rc != 0)
		(*errors)++;
	if (pgcfg->name_cache_timeout == 0)
		pgcfg->name_cache_timeout = NAME_CACHE_TMO_DEFAULT;

	rc = get_val_int(handles, "rediscovery_interval",
	    &pgcfg->rediscovery_interval, SCF_TYPE_COUNT);
	if (rc != 0)
		(*errors)++;
	if (pgcfg->rediscovery_interval == 0)
		pgcfg->rediscovery_interval = REDISCOVERY_INTERVAL_DEFAULT;

	rc = get_val_astring(handles, "domain_name",
	    &pgcfg->domain_name);
	if (rc != 0)
		(*errors)++;
	else {
		if (pgcfg->domain_name != NULL &&
		    pgcfg->domain_name[0] == '\0') {
			free(pgcfg->domain_name);
			pgcfg->domain_name = NULL;
		}
		(void) ad_disc_set_DomainName(handles->ad_ctx,
		    pgcfg->domain_name);
		pgcfg->domain_name_auto_disc = B_FALSE;
	}

	rc = get_val_astring(handles, "default_domain",
	    &pgcfg->default_domain);
	if (rc != 0) {
		/*
		 * SCF failures fetching config/default_domain we treat
		 * as fatal as they may leave ID mapping rules that
		 * match unqualified winnames flapping in the wind.
		 */
		return (-2);
	}

	if (pgcfg->default_domain == NULL && pgcfg->domain_name != NULL) {
		pgcfg->default_domain = strdup(pgcfg->domain_name);
	}

	rc = get_val_astring(handles, "domain_guid", &s);
	if (rc != 0) {
		(*errors)++;
	} else if (s == NULL || s[0] == '\0') {
		/* OK, not set. */
		free(s);
	} else {
		uuid_t u;

		if (uuid_parse(s, u) != 0) {
			idmapdlog(LOG_ERR,
		"config/domain_guid: invalid value \"%s\" ignored", s);
			free(s);
			(*errors)++;
		} else {
			pgcfg->domain_guid = s;
			pgcfg->domain_guid_auto_disc = B_FALSE;
			(void) ad_disc_set_DomainGUID(handles->ad_ctx, u);
		}
	}

	rc = get_val_astring(handles, "machine_uuid", &pgcfg->machine_uuid);
	if (rc != 0)
		(*errors)++;
	if (pgcfg->machine_uuid == NULL) {
		/* If machine_uuid not configured, generate one */
		if (generate_machine_uuid(&pgcfg->machine_uuid) < 0)
			return (-2);
		rc = set_val_astring(handles, handles->config_pg,
		    "machine_uuid", pgcfg->machine_uuid);
		if (rc != 0)
			(*errors)++;
	}

	rc = get_val_astring(handles, "machine_sid", &pgcfg->machine_sid);
	if (rc != 0)
		(*errors)++;
	if (pgcfg->machine_sid == NULL) {
		/*
		 * If machine_sid not configured, generate one
		 * from the machine UUID.
		 */
		if (generate_machine_sid(&pgcfg->machine_sid,
		    pgcfg->machine_uuid) < 0)
			return (-2);
		rc = set_val_astring(handles, handles->config_pg,
		    "machine_sid", pgcfg->machine_sid);
		if (rc != 0)
			(*errors)++;
	}

	rc = get_val_ds(handles, "domain_controller", 389,
	    &pgcfg->domain_controller);
	if (rc != 0)
		(*errors)++;
	else {
		(void) ad_disc_set_DomainController(handles->ad_ctx,
		    pgcfg->domain_controller);
		pgcfg->domain_controller_auto_disc = B_FALSE;
	}

	rc = get_val_ds(handles, "preferred_dc", 389,
	    &pgcfg->preferred_dc);
	if (rc != 0)
		(*errors)++;
	else {
		(void) ad_disc_set_PreferredDC(handles->ad_ctx,
		    pgcfg->preferred_dc);
		pgcfg->preferred_dc_auto_disc = B_FALSE;
	}

	rc = get_val_astring(handles, "forest_name", &pgcfg->forest_name);
	if (rc != 0)
		(*errors)++;
	else {
		(void) ad_disc_set_ForestName(handles->ad_ctx,
		    pgcfg->forest_name);
		pgcfg->forest_name_auto_disc = B_FALSE;
	}

	rc = get_val_astring(handles, "site_name", &pgcfg->site_name);
	if (rc != 0)
		(*errors)++;
	else
		(void) ad_disc_set_SiteName(handles->ad_ctx, pgcfg->site_name);

	rc = get_val_ds(handles, "global_catalog", 3268,
	    &pgcfg->global_catalog);
	if (rc != 0)
		(*errors)++;
	else {
		(void) ad_disc_set_GlobalCatalog(handles->ad_ctx,
		    pgcfg->global_catalog);
		pgcfg->global_catalog_auto_disc = B_FALSE;
	}

	/* Unless we're doing directory-based name mapping, we're done. */
	if (pgcfg->directory_based_mapping != DIRECTORY_MAPPING_NAME)
		return (0);

	rc = get_val_astring(handles, "ad_unixuser_attr",
	    &pgcfg->ad_unixuser_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->ad_unixuser_attr != NULL &&
	    !valid_ldap_attr(pgcfg->ad_unixuser_attr)) {
		idmapdlog(LOG_ERR, "config/ad_unixuser_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->ad_unixuser_attr);
		return (-3);
	}

	rc = get_val_astring(handles, "ad_unixgroup_attr",
	    &pgcfg->ad_unixgroup_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->ad_unixgroup_attr != NULL &&
	    !valid_ldap_attr(pgcfg->ad_unixgroup_attr)) {
		idmapdlog(LOG_ERR, "config/ad_unixgroup_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->ad_unixgroup_attr);
		return (-3);
	}

	rc = get_val_astring(handles, "nldap_winname_attr",
	    &pgcfg->nldap_winname_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->nldap_winname_attr != NULL &&
	    !valid_ldap_attr(pgcfg->nldap_winname_attr)) {
		idmapdlog(LOG_ERR, "config/nldap_winname_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->nldap_winname_attr);
		return (-3);
	}
	if (pgcfg->ad_unixuser_attr == NULL &&
	    pgcfg->ad_unixgroup_attr == NULL &&
	    pgcfg->nldap_winname_attr == NULL) {
		idmapdlog(LOG_ERR,
		    "If config/directory_based_mapping property is set to "
		    "\"name\" then at least one of the following name mapping "
		    "attributes must be specified. (config/ad_unixuser_attr OR "
		    "config/ad_unixgroup_attr OR config/nldap_winname_attr)");
		return (-3);
	}

	return (rc);
}

static
void
log_if_unable(const void *val, const char *what)
{
	if (val == NULL) {
		idmapdlog(LOG_DEBUG, "unable to discover %s", what);
	}
}

static
void
discover_trusted_domains(idmap_pg_config_t *pgcfg, ad_disc_t ad_ctx)
{
	ad_disc_t trusted_ctx;
	int i, j, k, l;
	char *forestname;
	int num_trusteddomains;
	boolean_t new_forest;
	char *trusteddomain;
	ad_disc_ds_t *globalcatalog;
	idmap_trustedforest_t *trustedforests;
	ad_disc_domainsinforest_t *domainsinforest;

	pgcfg->trusted_domains =
	    ad_disc_get_TrustedDomains(ad_ctx, NULL);

	if (pgcfg->forest_name != NULL && pgcfg->trusted_domains != NULL &&
	    pgcfg->trusted_domains[0].domain[0] != '\0') {
		/*
		 * We have trusted domains.  We need to go through every
		 * one and find its forest. If it is a new forest we then need
		 * to find its Global Catalog and the domains in the forest
		 */
		for (i = 0; pgcfg->trusted_domains[i].domain[0] != '\0'; i++)
			continue;
		num_trusteddomains = i;

		trustedforests = calloc(num_trusteddomains,
		    sizeof (idmap_trustedforest_t));
		j = 0;
		for (i = 0; pgcfg->trusted_domains[i].domain[0] != '\0'; i++) {
			trusteddomain = pgcfg->trusted_domains[i].domain;
			trusted_ctx = ad_disc_init();
			(void) ad_disc_set_DomainName(trusted_ctx,
			    trusteddomain);
			forestname =
			    ad_disc_get_ForestName(trusted_ctx, NULL);
			if (forestname == NULL) {
				if (DBG(CONFIG, 1)) {
					idmapdlog(LOG_DEBUG,
					    "unable to discover Forest Name"
					    " for the trusted domain %s",
					    trusteddomain);
				}
				ad_disc_fini(trusted_ctx);
				continue;
			}

			if (strcasecmp(forestname, pgcfg->forest_name) == 0) {
				/*
				 * Ignore the domain as it is part of
				 * the primary forest
				 */
				free(forestname);
				ad_disc_fini(trusted_ctx);
				continue;
			}

			/* Is this a new forest? */
			new_forest = B_TRUE;
			for (k = 0; k < j; k++) {
				if (strcasecmp(forestname,
				    trustedforests[k].forest_name) == 0) {
					new_forest = B_FALSE;
					domainsinforest =
					    trustedforests[k].domains_in_forest;
					break;
				}
			}
			if (!new_forest) {
				/* Mark the domain as trusted */
				for (l = 0;
				    domainsinforest[l].domain[0] != '\0'; l++) {
					if (domain_eq(trusteddomain,
					    domainsinforest[l].domain)) {
						domainsinforest[l].trusted =
						    TRUE;
						break;
					}
				}
				free(forestname);
				ad_disc_fini(trusted_ctx);
				continue;
			}

			/*
			 * Get the Global Catalog and the domains in
			 * this new forest.
			 */
			globalcatalog =
			    ad_disc_get_GlobalCatalog(trusted_ctx,
			    AD_DISC_PREFER_SITE, NULL);
			if (globalcatalog == NULL) {
				if (DBG(CONFIG, 1)) {
					idmapdlog(LOG_DEBUG,
					    "unable to discover Global Catalog"
					    " for the trusted domain %s",
					    trusteddomain);
				}
				free(forestname);
				ad_disc_fini(trusted_ctx);
				continue;
			}
			domainsinforest =
			    ad_disc_get_DomainsInForest(trusted_ctx, NULL);
			if (domainsinforest == NULL) {
				if (DBG(CONFIG, 1)) {
					idmapdlog(LOG_DEBUG,
					    "unable to discover Domains in the"
					    " Forest for the trusted domain %s",
					    trusteddomain);
				}
				free(globalcatalog);
				free(forestname);
				ad_disc_fini(trusted_ctx);
				continue;
			}

			trustedforests[j].forest_name = forestname;
			trustedforests[j].global_catalog = globalcatalog;
			trustedforests[j].domains_in_forest = domainsinforest;
			j++;
			/* Mark the domain as trusted */
			for (l = 0; domainsinforest[l].domain[0] != '\0';
			    l++) {
				if (domain_eq(trusteddomain,
				    domainsinforest[l].domain)) {
					domainsinforest[l].trusted = TRUE;
					break;
				}
			}
			ad_disc_fini(trusted_ctx);
		}
		if (j > 0) {
			pgcfg->num_trusted_forests = j;
			pgcfg->trusted_forests = trustedforests;
		} else {
			free(trustedforests);
		}
	}
}

/*
 * This is the half of idmap_cfg_load() that auto-discovers values of
 * discoverable properties that weren't already set via SMF properties.
 *
 * idmap_cfg_discover() is called *after* idmap_cfg_load_smf(), so it
 * needs to be careful not to overwrite any properties set in SMF.
 */
static void
idmap_cfg_discover1(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg)
{
	ad_disc_t ad_ctx = handles->ad_ctx;
	FILE *status_fp = NULL;
	time_t t0, t1;

	t0 = time(NULL);
	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Running domain discovery.");

	(void) unlink(IDMAP_CACHEDIR "/discovery.log");
	status_fp = fopen(IDMAP_CACHEDIR "/discovery.log", "w");
	if (status_fp) {
		(void) fchmod(fileno(status_fp), 0644);
		ad_disc_set_StatusFP(ad_ctx, status_fp);
	}

	if (pgcfg->domain_name == NULL) {
		idmapdlog(LOG_DEBUG, "No domain name specified.");
		if (status_fp)
			(void) fprintf(status_fp, "(no domain name)\n");
		goto out;
	}

	if (pgcfg->domain_controller == NULL)
		pgcfg->domain_controller =
		    ad_disc_get_DomainController(ad_ctx,
		    AD_DISC_PREFER_SITE,
		    &pgcfg->domain_controller_auto_disc);

	if (pgcfg->domain_guid == NULL) {
		char buf[UUID_PRINTABLE_STRING_LENGTH];
		uchar_t *u = ad_disc_get_DomainGUID(ad_ctx,
		    &pgcfg->domain_guid_auto_disc);
		(void) memset(buf, 0, sizeof (buf));
		if (u != NULL) {
			uuid_unparse(u, buf);
			pgcfg->domain_guid = strdup(buf);
		}
	}

	if (pgcfg->forest_name == NULL)
		pgcfg->forest_name = ad_disc_get_ForestName(ad_ctx,
		    &pgcfg->forest_name_auto_disc);

	if (pgcfg->site_name == NULL)
		pgcfg->site_name = ad_disc_get_SiteName(ad_ctx,
		    &pgcfg->site_name_auto_disc);

	if (DBG(CONFIG, 1)) {
		log_if_unable(pgcfg->domain_name, "Domain Name");
		log_if_unable(pgcfg->domain_controller,
		    "Domain Controller");
		log_if_unable(pgcfg->domain_guid, "Domain GUID");
		log_if_unable(pgcfg->forest_name, "Forest Name");
		log_if_unable(pgcfg->site_name, "Site Name");
	}

out:
	if (status_fp) {
		ad_disc_set_StatusFP(ad_ctx, NULL);
		(void) fclose(status_fp);
		status_fp = NULL;
	}

	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Domain discovery done.");

	/*
	 * Log when this took more than 15 sec.
	 */
	t1 = time(NULL);
	if (t1 > (t0 + 15)) {
		idmapdlog(LOG_NOTICE, "Domain discovery took %d sec.",
		    (int)(t1 - t0));
		idmapdlog(LOG_NOTICE, "Check the DNS configuration.");
	}
}

/*
 * This is the second part of discovery, which can take a while.
 * We don't want to hold up parties who just want to know what
 * domain controller we're using (like smbd), so this part runs
 * after we've updated that info in the "live" config and told
 * such consumers to go ahead.
 *
 * This is a lot like idmap_cfg_discover(), but used LDAP queries
 * get the forest information from the global catalog servers.
 *
 * Note: the previous update_* calls have usually nuked any
 * useful information from pgcfg before we get here, so we
 * can only use it store discovery results, not to read.
 */
static void
idmap_cfg_discover2(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg)
{
	ad_disc_t ad_ctx = handles->ad_ctx;
	FILE *status_fp = NULL;
	time_t t0, t1;

	t0 = time(NULL);
	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Running forest discovery.");

	status_fp = fopen(IDMAP_CACHEDIR "/discovery.log", "a");
	if (status_fp)
		ad_disc_set_StatusFP(ad_ctx, status_fp);

	if (pgcfg->global_catalog == NULL)
		pgcfg->global_catalog =
		    ad_disc_get_GlobalCatalog(ad_ctx,
		    AD_DISC_PREFER_SITE,
		    &pgcfg->global_catalog_auto_disc);

	if (pgcfg->global_catalog != NULL) {
		pgcfg->domains_in_forest =
		    ad_disc_get_DomainsInForest(ad_ctx, NULL);

		if (!pgcfg->disable_cross_forest_trusts)
			discover_trusted_domains(pgcfg, ad_ctx);
	}

	if (DBG(CONFIG, 1)) {
		log_if_unable(pgcfg->global_catalog, "Global Catalog");
		log_if_unable(pgcfg->domains_in_forest,
		    "Domains in the Forest");
		/* Empty trusted domains list is OK. */
	}

	if (status_fp) {
		ad_disc_set_StatusFP(ad_ctx, NULL);
		(void) fclose(status_fp);
		status_fp = NULL;
	}

	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Forest discovery done.");

	/*
	 * Log when this took more than 30 sec.
	 */
	t1 = time(NULL);
	if (t1 > (t0 + 30)) {
		idmapdlog(LOG_NOTICE, "Forest discovery took %d sec.",
		    (int)(t1 - t0));
		idmapdlog(LOG_NOTICE, "Check AD join status.");
	}
}


/*
 * idmap_cfg_load() is called at startup, and periodically via the
 * update thread when the auto-discovery TTLs expire, as well as part of
 * the refresh method, to update the current configuration.  It always
 * reads from SMF, but you still have to refresh the service after
 * changing the config pg in order for the changes to take effect.
 *
 * There is one flag:
 *
 *  - CFG_DISCOVER
 *
 * If CFG_DISCOVER is set then idmap_cfg_load() calls
 * idmap_cfg_discover() to discover, via DNS and LDAP lookups, property
 * values that weren't set in SMF.
 *
 * idmap_cfg_load() will log (to LOG_NOTICE) whether the configuration
 * changed.
 *
 * Return values: 0 -> success, -1 -> failure, -2 -> hard failures
 * reading from SMF.
 */
int
idmap_cfg_load(idmap_cfg_t *cfg, int flags)
{
	const ad_disc_t ad_ctx = cfg->handles.ad_ctx;
	int rc = 0;
	int errors;
	int changed = 0;
	int dc_changed = 0;
	int ad_reload_required = 0;
	idmap_pg_config_t new_pgcfg, *live_pgcfg;

	if (DBG(CONFIG, 1))
		idmapdlog(LOG_DEBUG, "Loading configuration.");

	live_pgcfg = &cfg->pgcfg;
	(void) memset(&new_pgcfg, 0, sizeof (new_pgcfg));

	(void) pthread_mutex_lock(&cfg->handles.mutex);

	if ((rc = idmap_cfg_load_smf(&cfg->handles, &new_pgcfg, &errors)) < -1)
		goto err;

	if (flags & CFG_DISCOVER) {

		ad_disc_refresh(ad_ctx);

		/*
		 * Unless we've been asked to forget the current DC,
		 * give preference (in order) to the preferred DC if
		 * configured, or the current DC.  These preferences
		 * reduce undesirable DC changes.
		 */
		if (flags & CFG_FORGET_DC) {
			(void) ad_disc_set_PreferredDC(ad_ctx, NULL);
		} else if (new_pgcfg.preferred_dc != NULL) {
			(void) ad_disc_set_PreferredDC(ad_ctx,
			    new_pgcfg.preferred_dc);
		} else if (live_pgcfg->domain_controller != NULL) {
			(void) ad_disc_set_PreferredDC(ad_ctx,
			    live_pgcfg->domain_controller);
		} else {
			(void) ad_disc_set_PreferredDC(ad_ctx, NULL);
		}

		/*
		 * We want a way to tell adspriv_getdcname_1_svc()
		 * (and others) that discovery is running and therefore
		 * they may want to wait a bit or return an error...
		 */
		(void) mutex_lock(&_idmapdstate.addisc_lk);
		_idmapdstate.addisc_st |= ADDISC_ST_RUNNING;
		(void) mutex_unlock(&_idmapdstate.addisc_lk);

		idmap_cfg_discover1(&cfg->handles, &new_pgcfg);

		WRLOCK_CONFIG();
		(void) mutex_lock(&_idmapdstate.addisc_lk);
		_idmapdstate.addisc_st = 0;
		(void) cond_broadcast(&_idmapdstate.addisc_cv);
		(void) mutex_unlock(&_idmapdstate.addisc_lk);
	} else {
		WRLOCK_CONFIG();
	}

	/* Non-discoverable props updated here */

	changed += update_uint64(&live_pgcfg->list_size_limit,
	    &new_pgcfg.list_size_limit, "list_size_limit");

	changed += update_uint64(&live_pgcfg->id_cache_timeout,
	    &new_pgcfg.id_cache_timeout, "id_cache_timeout");

	changed += update_uint64(&live_pgcfg->name_cache_timeout,
	    &new_pgcfg.name_cache_timeout, "name_cache_timeout");

	changed += update_uint64(&live_pgcfg->rediscovery_interval,
	    &new_pgcfg.rediscovery_interval, "rediscovery_interval");

	changed += update_string(&live_pgcfg->machine_sid,
	    &new_pgcfg.machine_sid, "machine_sid");

	changed += update_bool(&live_pgcfg->eph_map_unres_sids,
	    &new_pgcfg.eph_map_unres_sids, "unresolvable_sid_mapping");

	changed += update_bool(&live_pgcfg->use_ads,
	    &new_pgcfg.use_ads, "use_ads");

	changed += update_bool(&live_pgcfg->use_lsa,
	    &new_pgcfg.use_lsa, "use_lsa");

	changed += update_bool(&live_pgcfg->disable_cross_forest_trusts,
	    &new_pgcfg.disable_cross_forest_trusts,
	    "disable_cross_forest_trusts");

	changed += update_enum(&live_pgcfg->directory_based_mapping,
	    &new_pgcfg.directory_based_mapping, "directory_based_mapping",
	    directory_mapping_map);

	changed += update_string(&live_pgcfg->ad_unixuser_attr,
	    &new_pgcfg.ad_unixuser_attr, "ad_unixuser_attr");

	changed += update_string(&live_pgcfg->ad_unixgroup_attr,
	    &new_pgcfg.ad_unixgroup_attr, "ad_unixgroup_attr");

	changed += update_string(&live_pgcfg->nldap_winname_attr,
	    &new_pgcfg.nldap_winname_attr, "nldap_winname_attr");

	changed += update_string(&live_pgcfg->default_domain,
	    &new_pgcfg.default_domain, "default_domain");

	changed += update_dirs(&live_pgcfg->preferred_dc,
	    &new_pgcfg.preferred_dc, "preferred_dc");

	/* Props that can be discovered or set in SMF updated here */

	if (update_string(&live_pgcfg->domain_name,
	    &new_pgcfg.domain_name, "domain_name")) {
		changed++;
		ad_reload_required = TRUE;
		idmapd_set_krb5_realm(live_pgcfg->domain_name);
	}
	live_pgcfg->domain_name_auto_disc = new_pgcfg.domain_name_auto_disc;

	changed += update_string(&live_pgcfg->domain_guid,
	    &new_pgcfg.domain_guid, "domain_guid");
	live_pgcfg->domain_guid_auto_disc = new_pgcfg.domain_guid_auto_disc;

	dc_changed = update_dirs(&live_pgcfg->domain_controller,
	    &new_pgcfg.domain_controller, "domain_controller");
	changed += dc_changed;
	live_pgcfg->domain_controller_auto_disc =
	    new_pgcfg.domain_controller_auto_disc;

	changed += update_string(&live_pgcfg->forest_name,
	    &new_pgcfg.forest_name, "forest_name");
	live_pgcfg->forest_name_auto_disc = new_pgcfg.forest_name_auto_disc;

	changed += update_string(&live_pgcfg->site_name,
	    &new_pgcfg.site_name, "site_name");
	live_pgcfg->site_name_auto_disc = new_pgcfg.site_name_auto_disc;

	if (DBG(CONFIG, 1)) {
		if (changed)
			idmapdlog(LOG_NOTICE, "Configuration changed");
		else
			idmapdlog(LOG_NOTICE, "Configuration unchanged");
	}

	UNLOCK_CONFIG();

	if (dc_changed != 0) {
		notify_dc_changed();
	}

	/*
	 * Discovery2 can take a while.
	 */
	if (flags & CFG_DISCOVER) {
		if (live_pgcfg->domain_name != NULL &&
		    live_pgcfg->forest_name != NULL)
			idmap_cfg_discover2(&cfg->handles, &new_pgcfg);
		ad_disc_done(ad_ctx);
	}

	WRLOCK_CONFIG();

	/* More props that can be discovered or set in SMF */

	changed += update_dirs(&live_pgcfg->global_catalog,
	    &new_pgcfg.global_catalog, "global_catalog");
	live_pgcfg->global_catalog_auto_disc =
	    new_pgcfg.global_catalog_auto_disc;

	/* Props that are only discovered (never in SMF) */

	if (update_domains_in_forest(&live_pgcfg->domains_in_forest,
	    &new_pgcfg.domains_in_forest, "domains_in_forest")) {
		changed++;
		ad_reload_required = TRUE;
	}

	if (update_trusted_domains(&live_pgcfg->trusted_domains,
	    &new_pgcfg.trusted_domains, "trusted_domains")) {
		changed++;
		if (live_pgcfg->trusted_domains != NULL &&
		    live_pgcfg->trusted_domains[0].domain[0] != '\0')
			ad_reload_required = TRUE;
	}

	if (update_trusted_forest(&live_pgcfg->trusted_forests,
	    &live_pgcfg->num_trusted_forests, &new_pgcfg.trusted_forests,
	    &new_pgcfg.num_trusted_forests, "trusted_forest")) {
		changed++;
		if (live_pgcfg->trusted_forests != NULL)
			ad_reload_required = TRUE;
	}

	if (DBG(CONFIG, 1)) {
		if (changed)
			idmapdlog(LOG_NOTICE, "Configuration changed");
		else
			idmapdlog(LOG_NOTICE, "Configuration unchanged");
	}

	UNLOCK_CONFIG();

	if (ad_reload_required)
		reload_ad();

	idmap_cfg_unload(&new_pgcfg);

err:
	(void) pthread_mutex_unlock(&cfg->handles.mutex);

	if (rc < -1)
		return (rc);

	return ((errors == 0) ? 0 : -1);
}

/*
 * Initialize 'cfg'.
 */
idmap_cfg_t *
idmap_cfg_init()
{
	idmap_cfg_handles_t *handles;

	/* First the smf repository handles: */
	idmap_cfg_t *cfg = calloc(1, sizeof (idmap_cfg_t));
	if (!cfg) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (NULL);
	}
	handles = &cfg->handles;

	(void) pthread_mutex_init(&handles->mutex, NULL);

	if (!(handles->main = scf_handle_create(SCF_VERSION))) {
		idmapdlog(LOG_ERR, "scf_handle_create() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_handle_bind(handles->main) < 0) {
		idmapdlog(LOG_ERR, "scf_handle_bind() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (!(handles->service = scf_service_create(handles->main)) ||
	    !(handles->instance = scf_instance_create(handles->main)) ||
	    !(handles->config_pg = scf_pg_create(handles->main)) ||
	    !(handles->debug_pg = scf_pg_create(handles->main))) {
		idmapdlog(LOG_ERR, "scf handle creation failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_handle_decode_fmri(handles->main,
	    FMRI_BASE "/:properties/" CONFIG_PG,
	    NULL,				/* scope */
	    handles->service,		/* service */
	    handles->instance,		/* instance */
	    handles->config_pg,		/* pg */
	    NULL,				/* prop */
	    SCF_DECODE_FMRI_EXACT) < 0) {
		idmapdlog(LOG_ERR, "scf_handle_decode_fmri() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_service_get_pg(handles->service,
	    DEBUG_PG, handles->debug_pg) < 0) {
		idmapdlog(LOG_ERR, "Property group \"%s\": %s",
		    DEBUG_PG, scf_strerror(scf_error()));
		goto error;
	}

	check_smf_debug_mode(handles);

	/* Initialize AD Auto Discovery context */
	handles->ad_ctx = ad_disc_init();
	if (handles->ad_ctx == NULL)
		goto error;

	return (cfg);

error:
	(void) idmap_cfg_fini(cfg);
	return (NULL);
}

void
idmap_cfg_unload(idmap_pg_config_t *pgcfg)
{

	if (pgcfg->default_domain) {
		free(pgcfg->default_domain);
		pgcfg->default_domain = NULL;
	}
	if (pgcfg->domain_name) {
		free(pgcfg->domain_name);
		pgcfg->domain_name = NULL;
	}
	if (pgcfg->domain_guid) {
		free(pgcfg->domain_guid);
		pgcfg->domain_guid = NULL;
	}
	if (pgcfg->machine_sid) {
		free(pgcfg->machine_sid);
		pgcfg->machine_sid = NULL;
	}
	if (pgcfg->domain_controller) {
		free(pgcfg->domain_controller);
		pgcfg->domain_controller = NULL;
	}
	if (pgcfg->forest_name) {
		free(pgcfg->forest_name);
		pgcfg->forest_name = NULL;
	}
	if (pgcfg->site_name) {
		free(pgcfg->site_name);
		pgcfg->site_name = NULL;
	}
	if (pgcfg->global_catalog) {
		free(pgcfg->global_catalog);
		pgcfg->global_catalog = NULL;
	}
	if (pgcfg->trusted_domains) {
		free(pgcfg->trusted_domains);
		pgcfg->trusted_domains = NULL;
	}
	if (pgcfg->trusted_forests)
		free_trusted_forests(&pgcfg->trusted_forests,
		    &pgcfg->num_trusted_forests);

	if (pgcfg->ad_unixuser_attr) {
		free(pgcfg->ad_unixuser_attr);
		pgcfg->ad_unixuser_attr = NULL;
	}
	if (pgcfg->ad_unixgroup_attr) {
		free(pgcfg->ad_unixgroup_attr);
		pgcfg->ad_unixgroup_attr = NULL;
	}
	if (pgcfg->nldap_winname_attr) {
		free(pgcfg->nldap_winname_attr);
		pgcfg->nldap_winname_attr = NULL;
	}
}

int
idmap_cfg_fini(idmap_cfg_t *cfg)
{
	idmap_cfg_handles_t *handles = &cfg->handles;
	idmap_cfg_unload(&cfg->pgcfg);

	(void) pthread_mutex_destroy(&handles->mutex);
	scf_pg_destroy(handles->config_pg);
	if (handles->debug_pg != NULL)
		scf_pg_destroy(handles->debug_pg);
	scf_instance_destroy(handles->instance);
	scf_service_destroy(handles->service);
	scf_handle_destroy(handles->main);
	if (handles->ad_ctx != NULL)
		ad_disc_fini(handles->ad_ctx);
	free(cfg);

	return (0);
}

void
idmap_cfg_poke_updates(void)
{
	int prev_st;

	if (DBG(CONFIG, 1)) {
		idmapdlog(LOG_INFO, "idmap_cfg_poke_updates");
	}

	(void) mutex_lock(&_idmapdstate.addisc_lk);
	prev_st = _idmapdstate.addisc_st;
	_idmapdstate.addisc_st |= ADDISC_ST_REQUESTED;
	(void) mutex_unlock(&_idmapdstate.addisc_lk);

	if (prev_st & ADDISC_ST_REQUESTED) {
		idmapdlog(LOG_DEBUG, "already poked");
	} else {
		idmapdlog(LOG_DEBUG, "port send poke");
		(void) port_send(idmapd_ev_port, POKE_AUTO_DISCOVERY, NULL);
	}
}

void
idmap_cfg_force_rediscovery(void)
{
	int prev_st;

	if (DBG(CONFIG, 1)) {
		idmapdlog(LOG_INFO, "idmap_cfg_force_rediscovery");
	}

	(void) mutex_lock(&_idmapdstate.addisc_lk);
	prev_st = _idmapdstate.addisc_st;
	_idmapdstate.addisc_st |= ADDISC_ST_REQUESTED;
	(void) mutex_unlock(&_idmapdstate.addisc_lk);

	if (prev_st & ADDISC_ST_REQUESTED) {
		idmapdlog(LOG_DEBUG, "already kicked");
	} else {
		idmapdlog(LOG_DEBUG, "port send kick");
		(void) port_send(idmapd_ev_port, KICK_AUTO_DISCOVERY, NULL);
	}
}

/*ARGSUSED*/
void
idmap_cfg_hup_handler(int sig)
{
	if (idmapd_ev_port >= 0)
		(void) port_send(idmapd_ev_port, RECONFIGURE, NULL);
}

/*
 * Upgrade the debug flags.
 *
 * We're replacing a single debug flag with a fine-grained mechanism that
 * is also capable of considerably more verbosity.  We'll take a stab at
 * producing roughly the same level of output.
 */
static
int
upgrade_debug(idmap_cfg_handles_t *handles)
{
	boolean_t debug_present;
	const char DEBUG_PROP[] = "debug";
	int rc;

	rc = prop_exists(handles, DEBUG_PROP, &debug_present);

	if (rc != 0)
		return (rc);

	if (!debug_present)
		return (0);

	idmapdlog(LOG_INFO,
	    "Upgrading old %s/%s setting to %s/* settings.",
	    CONFIG_PG, DEBUG_PROP, DEBUG_PG);

	rc = set_val_integer(handles, handles->debug_pg, "config", 1);
	if (rc != 0)
		return (rc);
	rc = set_val_integer(handles, handles->debug_pg, "discovery", 1);
	if (rc != 0)
		return (rc);

	rc = del_val(handles, handles->config_pg, DEBUG_PROP);
	if (rc != 0)
		return (rc);

	return (0);
}

/*
 * Upgrade the DS mapping flags.
 *
 * If the old ds_name_mapping_enabled flag is present, then
 *     if the new directory_based_mapping value is present, then
 *         if the two are compatible, delete the old and note it
 *         else delete the old and warn
 *     else
 *         set the new based on the old, and note it
 *         delete the old
 */
static
int
upgrade_directory_mapping(idmap_cfg_handles_t *handles)
{
	boolean_t legacy_ds_name_mapping_present;
	const char DS_NAME_MAPPING_ENABLED[] = "ds_name_mapping_enabled";
	const char DIRECTORY_BASED_MAPPING[] = "directory_based_mapping";
	int rc;

	rc = prop_exists(handles, DS_NAME_MAPPING_ENABLED,
	    &legacy_ds_name_mapping_present);

	if (rc != 0)
		return (rc);

	if (!legacy_ds_name_mapping_present)
		return (0);

	boolean_t legacy_ds_name_mapping_enabled;
	rc = get_val_bool(handles, DS_NAME_MAPPING_ENABLED,
	    &legacy_ds_name_mapping_enabled, B_FALSE);
	if (rc != 0)
		return (rc);

	char *legacy_mode;
	char *legacy_bool_string;
	if (legacy_ds_name_mapping_enabled) {
		legacy_mode = "name";
		legacy_bool_string = "true";
	} else {
		legacy_mode = "none";
		legacy_bool_string = "false";
	}

	char *directory_based_mapping;
	rc = get_val_astring(handles, DIRECTORY_BASED_MAPPING,
	    &directory_based_mapping);
	if (rc != 0)
		return (rc);

	if (directory_based_mapping == NULL) {
		idmapdlog(LOG_INFO,
		    "Upgrading old %s=%s setting\n"
		    "to %s=%s.",
		    DS_NAME_MAPPING_ENABLED, legacy_bool_string,
		    DIRECTORY_BASED_MAPPING, legacy_mode);
		rc = set_val_astring(handles, handles->config_pg,
		    DIRECTORY_BASED_MAPPING, legacy_mode);
		if (rc != 0)
			return (rc);
	} else {
		boolean_t new_name_mapping;
		if (strcasecmp(directory_based_mapping, "name") == 0)
			new_name_mapping = B_TRUE;
		else
			new_name_mapping = B_FALSE;

		if (legacy_ds_name_mapping_enabled == new_name_mapping) {
			idmapdlog(LOG_INFO,
			    "Automatically removing old %s=%s setting\n"
			    "in favor of %s=%s.",
			    DS_NAME_MAPPING_ENABLED, legacy_bool_string,
			    DIRECTORY_BASED_MAPPING, directory_based_mapping);
		} else {
			idmapdlog(LOG_WARNING,
			    "Removing conflicting %s=%s setting\n"
			    "in favor of %s=%s.",
			    DS_NAME_MAPPING_ENABLED, legacy_bool_string,
			    DIRECTORY_BASED_MAPPING, directory_based_mapping);
		}
		free(directory_based_mapping);
	}

	rc = del_val(handles, handles->config_pg, DS_NAME_MAPPING_ENABLED);
	if (rc != 0)
		return (rc);

	return (0);
}

/*
 * Do whatever is necessary to upgrade idmap's configuration before
 * we load it.
 */
int
idmap_cfg_upgrade(idmap_cfg_t *cfg)
{
	int rc;

	rc = upgrade_directory_mapping(&cfg->handles);
	if (rc != 0)
		return (rc);

	rc = upgrade_debug(&cfg->handles);
	if (rc != 0)
		return (rc);

	return (0);
}

/*
 * The LDAP code passes principal names lacking any
 * realm information, which causes mech_krb5 to do
 * awful things trying to figure out the realm.
 * Avoid that by making sure it has a default,
 * even when krb5.conf is not configured.
 */
static void
idmapd_set_krb5_realm(char *domain)
{
	static char realm[MAXHOSTNAMELEN];
	size_t ilen, olen;
	int err;

	if (domain == NULL) {
		(void) unsetenv("KRB5_DEFAULT_REALM");
		return;
	}

	/* Convert to upper case, in place. */
	(void) strlcpy(realm, domain, sizeof (realm));
	olen = ilen = strlen(realm);
	(void) u8_textprep_str(realm, &ilen, realm, &olen,
	    U8_TEXTPREP_TOUPPER, U8_UNICODE_LATEST, &err);

	(void) setenv("KRB5_DEFAULT_REALM", realm, 1);
}
