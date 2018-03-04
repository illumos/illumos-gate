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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * DESCRIPTION: Contains top level functions to read/write to the DIT. These
 *		are the API between the shim and the mapping system.
 *		Things calling these should have no knowledge of LDAP. Things
 *		called by them should have no knowledge of NIS.
 *
 *		Error handling here may appear to be limited but, because the
 *		NIS protocol cannot carry meaningful information about why a
 *		N2L operation failed, functions that don't work log
 *		an error and then just return FAILURE.
 *
 */

/*
 * Includes. WE WANT TO USE REAL DBM FUNCTIONS SO DO NOT INCLUDE SHIM_HOOKS.H.
 */
#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <sys/systeminfo.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <errno.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "../ldap_structs.h"
#include "../ldap_parse.h"
#include "../nisdb_ldap.h"
#include "../ldap_util.h"
#include "../ldap_op.h"
#include "../ldap_attr.h"
#include "../nis_parse_ldap_conf.h"
#include "../nisdb_mt.h"
#include "yptol.h"
#include "dit_access_utils.h"
#include "stdio.h"

extern bool delete_map(char *name);
extern bool rename_map(char *from, char *to, bool_t secure_map);

/* Enable standard YP code features defined in ypdefs.h */
USE_YP_MASTER_NAME
USE_YP_DOMAIN_NAME
USE_YP_SECURE
USE_YP_INTERDOMAIN

/*
 * Decs
 */
suc_code add_special_entries(DBM *, map_ctrl *, bool_t *);
void free_null_terminated_list(char **list);


/*
 * FUNCTION:    is_yptol_mode();
 *
 * DESCRIPTION:	Determines if we should run in N2L or traditional mode based
 *		on the presence of the N2L mapping file. If there are problems
 *		with the file, e.g. unreadable, this will be picked up latter.
 *
 * INPUTS:     	Nothing
 *
 * OUTPUTS:   	TRUE = Run in N2L mode
 *		FALSE = Run in traditional mode.
 */
bool_t
is_yptol_mode()
{
	struct stat filestat;

	if (stat(YP_DEFAULTCONFFILE, &filestat) != -1)
		return (TRUE);

	return (FALSE);
}

/*
 * FUNCTION:    read_from_dit();
 *
 * DESCRIPTION:	Read (i.e. get and map) a single NIS entry from the LDAP DIT.
 *		Also handles retry attempts, on failure, and interpretation of
 *		internal error codes.
 *
 * INPUTS:     	Map name (unqualified)
 *		Domain name
 *		Entry key
 *		Pointer to return location
 *
 * OUTPUTS:   	If successful DBM datum containing result.
 *		On error DBM datum pointing to NULL and, if the cached value
 *		is not to be used, an error code.
 */
int
read_from_dit(char *map, char *domain, datum *key, datum *value)
{
	int count;
	int res;
	__nisdb_retry_t	*retrieveRetry;

	/* Initialize tsd */
	__nisdb_get_tsd()->domainContext = 0;
	__nisdb_get_tsd()->escapeFlag = '\0';

	for (count = 0; count < ypDomains.numDomains; count++) {
		if (0 == ypDomains.domainLabels[count])
			continue;
		if (0 == strcasecmp(domain, ypDomains.domainLabels[count])) {
			__nisdb_get_tsd()->domainContext =
			    ypDomains.domains[count];
			break;
		}
	}

	retrieveRetry = &ldapDBTableMapping.retrieveErrorRetry;

	/* Loop 'attempts' times of forever if -1 */
	for (count = retrieveRetry->attempts; (0 <= count) ||
	    (-1 == retrieveRetry->attempts); count --) {
		if (TRUE == singleReadFromDIT(map, domain, key, value, &res))
			/* It worked, return value irrelevant */
			return (0);

		if (LDAP_TIMEOUT == res) { /* Exceeded search timeout */
			value->dptr = NULL;
			return (0);
		}

		if (is_fatal_error(res))
			break;

		/*
		 * Didn't work. If not the special case where no repeats are
		 * done sleep.
		 */
		if (0 != retrieveRetry->attempts)
			(void) poll(NULL, 0, retrieveRetry->timeout*1000);
	}

	/* Make sure returned pointer is NULL */
	value->dptr = NULL;

	/* If we get here access failed work out what to return */
	if (ldapDBTableMapping.retrieveError == use_cached)
		return (0);

	return (res);
}

/*
 * FUNCTION:    write_to_dit();
 *
 * DESCRIPTION:	Maps and writes a NIS entry to the LDAP DIT.
 *		Also handles retry attempts, on failure, and interpretation of
 *		internal error codes.
 *
 * INPUTS:     	Pointer to (unqualified) map name
 *		Pointer to domain name
 *		The entries key
 *		What to write
 *		Replace flag indicating
 *			TRUE = Replace (overwrite) any existing entries
 *			FALSE = Return error if there are existing entries
 *		Flag indicating if we should tolerate mapping errors.
 *
 * OUTPUTS:   	SUCCESS = Write was successful
 *		FAILURE = Write failed
 *
 */
suc_code
write_to_dit(char *map, char *domain, datum key, datum value,
					bool_t replace, bool_t ignore_map_errs)
{
	int count;
	int res;
	__nisdb_retry_t	*storeRetry = &ldapDBTableMapping.storeErrorRetry;

	/* Initialize tsd */
	__nisdb_get_tsd()->domainContext = 0;
	__nisdb_get_tsd()->escapeFlag = '\0';

	for (count = 0; count < ypDomains.numDomains; count++) {
		if (0 == ypDomains.domainLabels[count])
			continue;
		if (0 == strcasecmp(domain, ypDomains.domainLabels[count])) {
			__nisdb_get_tsd()->domainContext =
			    ypDomains.domains[count];
			break;
		}
	}

	storeRetry = &ldapDBTableMapping.storeErrorRetry;

	/* Loop 'attempts' times of forever if -1 */
	for (count = storeRetry->attempts; (0 <= count) ||
	    (-1 == storeRetry->attempts); count --) {
		res = singleWriteToDIT(map, domain, &key, &value, replace);
		if (LDAP_SUCCESS == res)
			return (SUCCESS);

		if (is_fatal_error(res)) {
			/*
			 * The mapping failed and will fail again if it is
			 * retried. However there are some cases where an
			 * actual mapping fault (rather than a LDAP problem)
			 * may be ignored.
			 */
			if (ignore_map_errs) {
				switch (res) {
					case LDAP_INVALID_DN_SYNTAX:
					case LDAP_OBJECT_CLASS_VIOLATION:
					case LDAP_NOT_ALLOWED_ON_RDN:
					case MAP_NAMEFIELD_MATCH_ERROR:
					case MAP_NO_DN:
						return (SUCCESS);
					default:
						break;
				}
			}
			return (FAILURE);
		}

		if (ldapDBTableMapping.storeError != sto_retry)
			return (FAILURE);

		/*
		 * Didn't work. If not the special case where no repeats are
		 * done sleep.
		 */
		if (0 != storeRetry->attempts)
			(void) poll(NULL, 0, storeRetry->timeout*1000);

	}
	return (FAILURE);
}

/*
 * FUNCTION :	get_ttl_value()
 *
 * DESCRIPTION:	Get the TTL value, derived from mapping file or DIT, for a
 *		entry.
 *
 * GIVEN :	Pointer to map
 *		A flag indication if TTL should be max, min or random
 *
 * RETURNS :	TTL value in seconds.
 *		-1 on failure
 */
int
get_ttl_value(map_ctrl *map, TTL_TYPE type)
{
	__nis_table_mapping_t *table_map;
	int interval, res;
	char *myself = "get_ttl_value";

	/*  Get the mapping structure corresponding to `map.domain' */
	table_map = mappingFromMap(map->map_name, map->domain, &res);

	if (0 == table_map) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
		    "Get TTL request could not access map %s in domain %s "
		    "(error %d)", map->map_name, map->domain, res);
		return (-1);
	}

	switch (type) {
		case TTL_MAX:
			return (table_map->initTtlHi);

		case TTL_MIN:
			return (table_map->initTtlLo);

		default:
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s passed illegal TTL type (%d)", myself, type);
			/* If unknown TTL type drop through to TTL_RAND */
			/* FALLTHROUGH */

		case TTL_RAND:
			interval = table_map->initTtlHi - table_map->initTtlLo;
			if (0 >= interval)
				return (table_map->initTtlLo);

			/*
			 * Must get a random value. We assume srand48() got
			 * called at initialization.
			 */
			return (lrand48() % interval);

		case TTL_RUNNING:
			return (table_map->ttl);


	}
}

/*
 * FUNCTION :	get_mapping_domain_list()
 *
 * DESCRIPTION:	Gets a list of domain names specified, by nisLDAPdomainContext
 *		attributes, in the mapping file. This is used only for initial
 *		DIT setup. Once the DIT has been set up get_domain_list() is
 *		used instead.
 *
 * GIVEN :	Pointer returned array.
 *
 * RETURNS :	Number of element in returned array.
 *		Array of elements this is in static memory
 *		and must not be freed by the caller.
 */
int
get_mapping_domain_list(char ***ptr)
{
	*ptr = ypDomains.domainLabels;
	return (ypDomains.numDomains);
}

/*
 * FUNCTION :	get_mapping_yppasswdd_domain_list()
 *
 * DESCRIPTION:	Gets a list of domain names specified, by the
 *		nisLDAPyppasswddDomains attribute, in the mapping file. This
 *		is the list of domains for which passwords should be changed.
 *
 * GIVEN :	Pointer returned array
 *
 * RETURNS :	Number of element in returned array.
 *		0 if no nisLDAPyppasswddDomains attribute is present.
 *		Array of elements this is in static memory
 *		and must not be freed by the caller.
 */
int
get_mapping_yppasswdd_domain_list(char ***ptr)
{
	*ptr = ypDomains.yppasswddDomainLabels;
	return (ypDomains.numYppasswdd);
}

/*
 * FUNCTION :	free_map_list()
 *
 * DESCRIPTION:	Frees a map list.
 *
 * GIVEN :	Pointer to the map list.
 *
 * RETURNS :	Nothing
 */
void
free_map_list(char **map_list)
{
	free_null_terminated_list(map_list);
}

/*
 * FUNCTION :	get_passwd_list()
 *
 * DESCRIPTION:	Gets a list of either passwd or passwd.adjunct map files
 *		defined in the mapping file. These are the files which have
 *		'magic' nisLDAPdatabaseIdMapping entries aliasing them to
 *		passwd or passwd.adjunct. This function is required so that
 *		yppasswdd can work out which maps to synchronize with any
 *		password changes.
 *
 *		This information is not currently stored by the parser but
 *		we can recover it from the hash table. This makes hard work but
 *		passwords should not be changed very frequently
 *
 * GIVEN :	Flag indicating if a list is required for passwd or
 *		passwd.adjunct
 *		Domain to return the list for.
 *
 * RETURNS :	Null terminated list of map names in malloced memory. To be
 *		freed by caller. (Possibly empty if no passwd maps found)
 *		NULL on error
 */
char **
get_passwd_list(bool_t adjunct, char *domain)
{
	char *myself = "get_passwd_list";
	__nis_hash_item_mt *it;
	int	i, size;
	char 	*end_ptr;
	char	*target;	/* What we are looking for */
	int	target_len;
	int	domain_len;
	char	**res;		/* Result array */
	char	**res_old;	/* Old value of res during realloc */
	int	array_size;	/* Current malloced size */
	int	res_count = 0;	/* Current result count */

	/*
	 * Always need an array even if just for terminator. Normally one
	 * chunk will be enough.
	 */
	res = am(myself, ARRAY_CHUNK * sizeof (char *));
	if (NULL == res)
		return (NULL);
	array_size = ARRAY_CHUNK;

	/* Set up target */
	if (adjunct)
		target = PASSWD_ADJUNCT_PREFIX;
	else
		target = PASSWD_PREFIX;
	target_len = strlen(target);
	domain_len = strlen(domain);

	/* Work out hash table length */
	size = sizeof (ldapMappingList.keys) / sizeof (ldapMappingList.keys[0]);
	/* For all hash table entries */
	for (i = 0; i < size; i++) {
		/* Walk linked list for this hash table entry */
		for (it = ldapMappingList.keys[i]; NULL != it; it = it->next) {
			/* Check right map */
			if ((target_len + domain_len + 1) > strlen(it->name))
				continue;
			if (0 != strncmp(it->name, target, target_len))
				continue;

			/* Check right domain (minus trailing dot) */
			if (strlen(domain) >= strlen(it->name))
				continue;
			end_ptr = it->name + strlen(it->name) -
			    strlen(domain) - 1;
			if (',' != *(end_ptr - 1))
				continue;
			if (0 != strncmp(end_ptr, domain, strlen(domain)))
				continue;

			/* Check if we need to enlarge array */
			if ((res_count + 1) >= array_size) {
				array_size += ARRAY_CHUNK;
				res_old = res;
				res = realloc(res, array_size *
				    sizeof (char *));
				if (NULL == res) {
					res_old[res_count] = NULL;
					free_passwd_list(res_old);
					return (NULL);
				}
			}

			/* What we really need is strndup() */
			res[res_count] = am(myself, end_ptr - it->name + 1);
			if (NULL == res[res_count]) {
				free_passwd_list(res);
				return (NULL);
			}

			/* Copy from start to end_ptr */
			(void) memcpy(res[res_count], it->name,
			    end_ptr-it->name - 1);
			res_count ++;
		}
	}

	/* Terminate array */
	res[res_count] = NULL;
	return (res);
}

/*
 * FUNCTION :	free_passwd_list()
 *
 * DESCRIPTION:	Frees a password list obtained with get_passwd_list()
 *
 * INPUTS :	Address of list to free.
 *
 * OUTPUTS :	Nothing
 */
void
free_passwd_list(char **list)
{
	free_null_terminated_list(list);
}

/*
 * FUNCTION :	free_null_terminated_list()
 *
 * DESCRIPTION:	Frees a generic null terminated list.
 *
 * INPUTS :	Address of list to free.
 *
 * OUTPUTS :	Nothing
 */
void
free_null_terminated_list(char **list)
{
	int index;

	/* Free all the strings */
	for (index = 0; NULL != list[index]; index ++)
		sfree(list[index]);

	/* Free the array */
	sfree(list);
}


/*
 * FUNCTION :	add_special_entries()
 *
 * DESCRIPTION:	Adds the special (YP_*) entries to a map.
 *
 *		Part of dit_access because requires access to the mapping
 *		file in order to work out if secure and interdomain entries
 *		should be created.
 *
 * GIVEN :	Pointer to an open, temporary, DBM file
 *		Pointer to map information (do not use DBM fields).
 *		Pointer to a location in which to return security flag
 *
 * RETURNS :	SUCCESS = All entries created
 *		FAILURE = Some entries not created
 */
suc_code
add_special_entries(DBM *db, map_ctrl *map, bool_t *secure_flag)
{
	char local_host[MAX_MASTER_NAME];
	__nis_table_mapping_t *table_map;
	int res;

	/* Last modified time is now */
	update_timestamp(db);

	/* Add domain name */
	addpair(db, yp_domain_name, map->domain);

	/* For N2L mode local machine is always the master */
	sysinfo(SI_HOSTNAME, local_host, sizeof (local_host));
	addpair(db, yp_master_name, local_host);

	/*  Get the mapping structure corresponding to `map.domain' */
	table_map = mappingFromMap(map->map_name, map->domain, &res);
	if (0 == table_map)
		return (FAILURE);

	/* Add secure and interdomain flags if required */
	if (table_map->securemap_flag) {
		addpair(db, yp_secure, "");
		*secure_flag = TRUE;
	} else {
		*secure_flag = FALSE;
	}
	if (table_map->usedns_flag)
		addpair(db, yp_interdomain, "");

	return (SUCCESS);
}

/*
 * FUNCTION:	update_map_from_dit()
 *
 * DESCRIPTION:	Core code called to update an entire map.
 *		Information is recovered from LDAP and used to build a duplicate
 *		copy of the live maps. When this is complete the maps are
 *		locked and then overwritten by the new copy.
 *
 * INPUTS:	map_ctrl containing lots of information about the map and a
 *		pointer to it's lock which will be required.
 *		Flag indicating if progress logging is required.
 *
 * OUTPUTS:	SUCCESS = Map updated
 *		FAILURE = Map not updated
 */
suc_code
update_map_from_dit(map_ctrl *map, bool_t log_flag) {
	__nis_table_mapping_t	*t;
	__nis_rule_value_t	*rv;
	__nis_ldap_search_t	*ls;
	__nis_object_dn_t	*objectDN = NULL;
	datum			*datval, *datkey;
	int			nr = 0, i, j, nv, numDNs;
	int			statP = SUCCESS, flag;
	char			*objname, **dn;
	/* Name of temporary entries DBM file */
	char			*temp_entries;
	/* Name of temporary TTL DBM file */
	char			*temp_ttl;
	/* Temporary DBM handles */
	DBM			*temp_entries_db;
	DBM			*temp_ttl_db;
	map_ctrl		temp_map;
	datum			key;
	char			*myself = "update_map_from_dit";
	bool_t			secure_flag;
	int			entry_count = 1;
	int			next_print = PRINT_FREQ;
	int			search_flag = SUCCESS;

	int			m;

	/* list of maps whose keys will be transliterated to lowercase */
	char			*xlate_to_lcase_maps[] = {
		"hosts.byname",
		"ipnodes.byname",
		NULL
	};
	bool_t			xlate_to_lcase = FALSE;

	if (!map || !map->map_name || !map->domain) {
		return (FAILURE);
	}

	__nisdb_get_tsd()->escapeFlag = '\0';

	/*
	 * netgroup.byxxx maps are a special case. They are regenerated from
	 * the netgroup map, not the DIT, so handle special case.
	 */
	if ((0 == strcmp(map->map_name, NETGROUP_BYHOST)) ||
		0 == (strcmp(map->map_name,  NETGROUP_BYUSER))) {
		return (update_netgroup_byxxx(map));
	}

	/* Get the mapping information for the map */
	if ((t = mappingFromMap(map->map_name, map->domain, &statP)) == 0) {
		if (statP == MAP_NO_MAPPING_EXISTS)
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: No mapping information available for %s,%s",
				myself, map->map_name, map->domain);
		return (FAILURE);
	}

	/* Allocate and set up names */
	if (SUCCESS != alloc_temp_names(map->map_path,
				&temp_entries, &temp_ttl)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to create map names for %s",
			myself, map->map_path);
		return (FAILURE);
	}

	/* Create temp entry and TTL file */
	if ((temp_entries_db = dbm_open(temp_entries, O_RDWR | O_CREAT, 0644))
						== NULL) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not open %s",
						myself, temp_entries);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	if ((temp_ttl_db = dbm_open(temp_ttl, O_RDWR | O_CREAT, 0644))
						== NULL) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not open %s",
						myself, temp_ttl);
		dbm_close(temp_entries_db);
		delete_map(temp_entries);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	/* Initialize domainContext tsd */
	__nisdb_get_tsd()->domainContext = 0;
	for (i = 0; i < ypDomains.numDomains; i++) {
		if (0 == ypDomains.domainLabels[i])
			continue;
		if (0 == strcasecmp(map->domain, ypDomains.domainLabels[i])) {
			__nisdb_get_tsd()->domainContext = ypDomains.domains[i];
			break;
		}
	}

	if (!(objname = getFullMapName(map->map_name, map->domain))) {
		if (temp_entries_db)
			dbm_close(temp_entries_db);
		if (temp_ttl_db)
			dbm_close(temp_ttl_db);
		delete_map(temp_entries);
		sfree(temp_entries);
		delete_map(temp_ttl);
		sfree(temp_ttl);
		return (FAILURE);
	}

	/*
	 * set xlate_to_lcase to TRUE if map_name is found in
	 * xlate_to_lcase_maps[]
	 */
	m = 0;
	while (xlate_to_lcase_maps[m] != NULL) {
		if (strncmp(map->map_name, xlate_to_lcase_maps[m],
			strlen(xlate_to_lcase_maps[m])) == 0) {
			xlate_to_lcase = TRUE;
			break;
		}
		++m;
	}

	/* Try each mapping for the map */
	for (flag = 0; t != 0 && search_flag != FAILURE; t = t->next) {

		/* Check if the mapping is the correct one */
		if (strcmp(objname, t->objName) != 0) {
			continue;
		}

		/* Check if rulesFromLDAP are provided */
		if (t->numRulesFromLDAP == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: No rulesFromLDAP available for %s (%s)",
				myself, t->dbId, map->map_name);
			continue;
		}

		/* Set flag to indicate update is enabled */
		flag = 1;
		/* Create ldap request for enumeration */
		for (objectDN = t->objectDN;
				objectDN && objectDN->read.base;
				objectDN = objectDN->next) {
			if ((ls = createLdapRequest(t, 0, 0, 1, NULL,
						objectDN)) == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Failed to create "
					"ldapSearch request for "
					"%s (%s) for base %s",
					myself, t->dbId,
					map->map_name,
					objectDN->read.base);
				statP = FAILURE;
				search_flag = FAILURE;
				break;
			}

			if (log_flag) {
				printf("Waiting for LDAP search results.\n");
			}

			/* Query LDAP */
			nr = (ls->isDN)?0:-1;
			rv = ldapSearch(ls, &nr, 0, &statP);
			freeLdapSearch(ls);
			if (rv == 0) {
				if (statP == LDAP_NO_SUCH_OBJECT) {
				/*
				 * No Entry exists in the ldap server. Not
				 * a problem. Maybe there are just no entries
				 * in this map.
				 */
					continue;
				}
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: ldapSearch error %d "
					"(%s) for %s (%s) for base %s",
					myself, statP, ldap_err2string(statP),
					t->dbId, map->map_name,
					objectDN->read.base);
				statP = FAILURE;
				search_flag = FAILURE;
				break;
			}

			if (log_flag) {
				printf("Processing search results.\n");
			}

			/* Obtain list of DNs for logging */
			if ((dn = findDNs(myself, rv, nr, 0, &numDNs)) == 0) {
				statP = FAILURE;
				search_flag = FAILURE;
				break;
			}

			/* For each entry in the result  do the following */
			for (i = 0; i < nr; i++) {
			/* Convert LDAP data to NIS equivalents */
				statP = buildNISRuleValue(t, &rv[i],
						map->domain);
				if (statP == MAP_INDEXLIST_ERROR)
					continue;
				if (statP != SUCCESS) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					    "%s: Conversion error %d (LDAP to "
					    "name=value pairs) "
					    "for (dn: %s) for "
					    "%s (%s) for base %s",
					    myself, statP, NIL(dn[i]),
					    t->dbId, map->map_name,
					    objectDN->read.base);
					continue;
				}

				/* Obtain the datum for value */
				datval = ruleValueToDatum(t, &rv[i], &statP);
				if (datval == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s: Conversion error %d "
						"(name=value pairs to NIS)"
						" for (dn: %s) for "
						"%s (%s) for base %s",
						myself, statP, NIL(dn[i]),
						t->dbId, map->map_name,
						objectDN->read.base);
					continue;
				}

				/* Obtain the datum for key */
				datkey = getKeyFromRuleValue(t, &rv[i],
				    &nv, &statP, xlate_to_lcase);
				if (datkey == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s: Unable to obtain NIS "
						"key from LDAP data (dn:%s) "
						"for %s (%s) for base %s",
						myself, NIL(dn[i]), t->dbId,
						map->map_name,
						objectDN->read.base);
					sfree(datval->dptr);
					sfree(datval);
					continue;
				}

				/* Write to the temporary map */
				for (j = 0; j < nv; j++, entry_count ++) {
					if (datkey[j].dsize == 0)
						continue;
					errno = 0;
					/* DBM_INSERT to match */
					/* singleReadFromDIT */
					if (dbm_store(temp_entries_db,
						datkey[j],
						*datval,
						DBM_INSERT) < 0) {
						/*
						 * For some cases errno may
						 * still be 0 but dbm_error
						 * isn't informative at all.
						 */
						logmsg(MSG_NOTIMECHECK,
						    LOG_WARNING,
						    "%s: dbm store error "
						    "(errno=%d) "
						    "for (key=%s, value=%s) "
						    "for %s (%s) for base %s",
						    myself,
						    errno,
						    datkey[j].dptr,
						    datval->dptr, t->dbId,
						    map->map_name,
						    objectDN->read.base);
						/* clear the error */
						dbm_clearerr(temp_entries_db);
					}
					sfree(datkey[j].dptr);

					if (log_flag && (entry_count >=
							next_print)) {
						printf("%d entries processed\n",
							entry_count);
						next_print *= 2;
					}

				}
				sfree(datkey);
				sfree(datval->dptr);
				sfree(datval);
			}

			freeRuleValue(rv, nr);
			freeDNs(dn, numDNs);
		} /* End of for over objectDN */
	}
	sfree(objname);

	if (t != 0 || flag == 0 || search_flag == FAILURE) {
		if (temp_entries_db)
			dbm_close(temp_entries_db);
		if (temp_ttl_db)
			dbm_close(temp_ttl_db);
		delete_map(temp_entries);
		sfree(temp_entries);
		delete_map(temp_ttl);
		sfree(temp_ttl);
		return (statP);
	}
	/* Set up enough of map_ctrl to call update_entry_ttl */
	temp_map.map_name = map->map_name;
	temp_map.domain = map->domain;
	temp_map.ttl = temp_ttl_db;

	/* Generate new TTL file */
	key = dbm_firstkey(temp_entries_db);
	while (key.dptr != 0) {
		if (!is_special_key(&key))
			/*
			 * We don't want all the entries to time out at the
			 * same time so create random TTLs.
			 */
			if (FAILURE == update_entry_ttl(&temp_map, &key,
								TTL_RAND))
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Could not update TTL for "
					"(key=%s) for map %s,%s",
					myself, NIL(key.dptr), map->map_name,
					map->domain);
		key = dbm_nextkey(temp_entries_db);
	}

	/* Update map TTL */
	if (SUCCESS != update_map_ttl(&temp_map)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not update map TTL "
			"for %s,%s", myself, map->map_name, map->domain);
	}

	/* Set up 'special' nis entries */
	add_special_entries(temp_entries_db, map, &secure_flag);

	/* Close temp DBM files */
	dbm_close(temp_entries_db);
	dbm_close(temp_ttl_db);

	/* Lock access to the map for copy */
	lock_map_ctrl(map);

	/* Move temp maps to real ones */
	rename_map(temp_entries, map->map_path, secure_flag);
	rename_map(temp_ttl, map->ttl_path, secure_flag);

	/* Free file names */
	sfree(temp_entries);
	sfree(temp_ttl);

	/* Unlock map */
	unlock_map_ctrl(map);

	return (SUCCESS);
}

/*
 * FUNCTION :	get_mapping_map_list()
 *
 * DESCRIPTION:	Gets a list of nis maps for a given domain specified in the
 *		mapping file. This information is not saved so have to go
 *		through the entire hash table. At least this is only done at
 *		initialization time.
 *
 * GIVEN :	Domain name
 *
 * RETURNS :	List of map names in malloced memory. MUST BE FREED BY CALLER.
 */
char **
get_mapping_map_list(char *domain)
{
	char *myself = "get_mapping_map_list";
	__nis_hash_item_mt *it;
	int	i, j, size;
	char 	*end_ptr;
	char	**res;		/* Result array */
	char	**res_old;	/* Old value of res during realloc */
	int	array_size;	/* Current malloced size */
	int	res_count = 0;	/* Current result count */

	/*
	 * Always need an array even if just for terminator. Normally one
	 * chunk will be enough.
	 */
	res = am(myself, ARRAY_CHUNK * sizeof (char *));
	if (NULL == res)
		return (NULL);
	array_size = ARRAY_CHUNK;

	/* Work out hash table length */
	size = sizeof (ldapMappingList.keys) / sizeof (ldapMappingList.keys[0]);
	/* For all hash table entries */
	for (i = 0; i < size; i++) {
		/* Walk linked list for this hash table entry */
		for (it = ldapMappingList.keys[i]; NULL != it; it = it->next) {

			/* Check it's not a split field entry */
			if (0 != ((__nis_table_mapping_t *)it)->numSplits)
				continue;

			/* Check right domain (minus trailing dot) */
			if (strlen(domain) >= strlen(it->name))
				continue;
			end_ptr = it->name + strlen(it->name) -
			    strlen(domain) - 1;
			if (',' != *(end_ptr - 1))
				continue;
			if (0 != strncmp(end_ptr, domain, strlen(domain)))
				continue;

			/* Check if we need to enlarge array */
			if ((res_count + 1) >= array_size) {
				array_size += ARRAY_CHUNK;
				res_old = res;
				res = realloc(res, array_size *
				    sizeof (char *));
				if (NULL == res) {
					res_old[res_count] = NULL;
					free_passwd_list(res_old);
					return (NULL);
				}
			}

			/*
			 * We will need the sequence number when we come to
			 * sort the entries so for now store a pointer to
			 * the __nis_hash_item_mt.
			 */
			res[res_count] = (char *)it;
			res_count ++;
		}
	}

	/* Terminate array */
	res[res_count] = NULL;

	/* Bubble sort entries into the same order as mapping file */
	for (i = res_count - 2; 0 <= i; i--) {
		for (j = 0; j <= i; j++) {
			if (((__nis_table_mapping_t *)res[j + 1])->seq_num <
			    ((__nis_table_mapping_t *)res[j])->seq_num) {
				end_ptr = res[j];
				res[j] = res[j+1];
				res[j + 1] = end_ptr;
			}
		}
	}

	/* Finally copy the real strings in to each entry */
	for (i = 0; NULL != res[i]; i ++) {

		/* Get hash table entry back */
		it = (__nis_hash_item_mt *)res[i];

		end_ptr = it->name + strlen(it->name) - strlen(domain) - 1;

		/* What we really need is strndup() */
		res[i] = am(myself, end_ptr - it->name + 1);
		if (NULL == res[i]) {
			free_map_list(res);
			return (NULL);
		}

		/* Copy from start to end_ptr */
		(void) memcpy(res[i], it->name, end_ptr-it->name - 1);
	}

	return (res);
}

/*
 * FUNCTION :	make_nis_container()
 *
 * DESCRIPTION: Sets up container for map_name in the DIT.
 *
 * GIVEN :	Map name
 *		The domain name.
 *		Flag indicating if container should be created.
 *
 * RETURNS :	SUCCESS	= It worked
 *		FAILURE	= There was a problem.
 */
suc_code
make_nis_container(char *map_name, char *domain, bool_t init_containers) {
	int			i, rc, statP = SUCCESS;
	__nis_table_mapping_t	*t;
	char			*dn;
	char			*myself = "make_nis_container";

	if (!map_name || !domain)
		return (FAILURE);

	if (FALSE == init_containers) {
		/*
		 * If we are not creating containers it is debatable what we
		 * should do . Maybe we should check for a pre-
		 * existing container and return failure if it does not exist.
		 *
		 * For now we assume the user will not have called us in this
		 * mode unless they know what they are doing. So return
		 * success. If they have got it wrong then latter writes will
		 * fail.
		 */
		return (SUCCESS);
	}

	/* Get the mapping information for the map */
	if ((t = mappingFromMap(map_name, domain, &statP)) == 0) {
		if (statP == MAP_NO_MAPPING_EXISTS)
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: No mapping information available for %s,%s",
				myself, NIL(map_name), NIL(domain));
		return (FAILURE);
	}

	/* Two times. One for readDN and other for writeDN */
	for (i = 0; i < 2; i++) {
		if (i == 0)
			dn = t->objectDN->read.base;
		else {
			if (t->objectDN->write.base == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: No baseDN in writespec. Write "
					"disabled for %s,%s",
					myself, map_name, domain);
				break;
			}
			if (!strcasecmp(dn, t->objectDN->write.base))
				break;
			dn = t->objectDN->write.base;
		}

		if ((rc = makeNISObject(0, dn)) == FAILURE) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to create ldap container (dn: %s) "
				"for %s,%s", myself, dn, map_name, domain);
			return (FAILURE);
		}
	}
	return (SUCCESS);
}

/*
 * FUNCTION :	make_nis_domain()
 *
 * DESCRIPTION:	Sets up a nisDomainObject in the DIT
 *
 * GIVEN:	Name of the domain
 *		Flag indicating if domain should be create or possibly just
 *		checked for.
 */
suc_code
make_nis_domain(char *domain, bool_t init_containers) {

	if (FALSE == init_containers) {
		/*
		 * If we are not creating containers it is debatable what we
		 * should do with domains. Maybe we should check for a pre-
		 * existing domain and return failure if it does not exist.
		 *
		 * For now we assume the user will not have called us in this
		 * mode unless they know what they are doing. So return
		 * success. If they have got it wrong then latter writes will
		 * fail.
		 */
		return (SUCCESS);
	}

	/* Create the domain */
	return (makeNISObject(domain, 0));
}

/*
 * FUNCTION:	update_netgroup_byxxx()
 *
 * DESCRIPTION:	Updates the netgroup.byxxx series of maps based on the current
 *		netgroup file. We invoke revnetgroup so that if any changes
 *		are made to this utility the same changes are made here.
 *
 * INPUTS:	map_ctrl containing lots of information about the map and a
 *		pointer to it's lock which will be required.
 *
 * OUTPUTS:	SUCCESS = Map updated
 *		FAILURE = Map not updated
 */
suc_code
update_netgroup_byxxx(map_ctrl *map) {
	/* Name of temporary entries DBM file */
	char			*temp_entries;
	/* Name of temporary TTL DBM file */
	char			*temp_ttl;
	/* Temporary DBM handles */
	DBM			*temp_entries_db;
	DBM			*temp_ttl_db;
	map_ctrl		temp_map;
	char			*myself = "update_netgroup_byxxx";
	char			*cmdbuf;
	int			cmd_length;
	datum			key;
	map_ctrl		*netgroupmap;
	int			res;
	/* Temporary revnetgroup files */
	const char 		*byhost = NETGROUP_BYHOST "_REV" TEMP_POSTFIX;
	const char 		*byuser = NETGROUP_BYUSER "_REV" TEMP_POSTFIX;
	const char		*temp_file_name;


	/*
	 * We need to use two different temporary files: one for netgroup.byhost
	 * and other for netgroup.byuser, since these two maps can be updated
	 * simultaneously. These temporary files will hold the output of
	 * revnetgroup [-h|-u] command. They are then used to generate the
	 * corresponding dbm files and thereafter deleted.
	 */
	if (0 == strcmp(map->map_name, NETGROUP_BYHOST))
		temp_file_name = byhost;
	else
		temp_file_name = byuser;

	/* Alloc enough cmd buf for revnet cmd */
	cmd_length = strlen("/usr/sbin/makedbm -u ") +
			(strlen(map->map_path) - strlen(map->map_name)) +
			strlen(NETGROUP_MAP) +
			strlen(" | /usr/sbin/revnetgroup -h > ") +
			(strlen(map->map_path) - strlen(map->map_name)) +
			strlen(temp_file_name) + 1;
	cmdbuf = am(myself, cmd_length);

	if (NULL == cmdbuf) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Could not alloc cmdbuf.", myself);
		return (FAILURE);
	}

	/*
	 * If necessary update (and wait for) netgroups map. This is a lot of
	 * work but if the netgroup map itself is not being accessed it may
	 * contain information that is not up to date with the DIT.
	 *
	 * We use the cmdbuf to store the qualified netgroup map name there will
	 * be enough space for this but we are not yet creating the cmd.
	 */
	strlcpy(cmdbuf, map->map_path, strlen(map->map_path) -
						strlen(map->map_name) + 1);
	strcat(cmdbuf, NETGROUP_MAP);
	netgroupmap = (map_ctrl *)shim_dbm_open(cmdbuf,
						O_RDWR | O_CREAT, 0644);
	if (NULL == netgroupmap) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Could not update %s.", myself, cmdbuf);
		sfree(cmdbuf);
		return (FAILURE);
	}

	if (has_map_expired(netgroupmap)) {
		lock_map_ctrl(netgroupmap);
		update_map_if_required(netgroupmap, TRUE);
		unlock_map_ctrl(netgroupmap);
	}
	shim_dbm_close((DBM *)netgroupmap);

	/* Dump netgroup file through revnetgroup to a temp file */
	strcpy(cmdbuf, "/usr/sbin/makedbm -u ");

	/* Unmake the netgroup file in same domain as map */
	strncat(cmdbuf, map->map_path, strlen(map->map_path) -
						strlen(map->map_name));
	strcat(cmdbuf, NETGROUP_MAP);

	if (0 == strcmp(map->map_name, NETGROUP_BYHOST)) {
		strcat(cmdbuf, " | /usr/sbin/revnetgroup -h > ");
	} else {
		strcat(cmdbuf, " | /usr/sbin/revnetgroup -u > ");
	}

	/* Create temp file file in same domain as map */
	strncat(cmdbuf, map->map_path, strlen(map->map_path) -
						strlen(map->map_name));
	strcat(cmdbuf, temp_file_name);

	if (0 > system(cmdbuf)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not run \"%s\" "
			"(errno=%d)", myself, cmdbuf, errno);
		sfree(cmdbuf);
		return (FAILURE);
	}
	sfree(cmdbuf);

	/* Allocate and set up names */
	if (SUCCESS != alloc_temp_names(map->map_path,
				&temp_entries, &temp_ttl)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to create map names for %s",
			myself, map->map_path);
		return (FAILURE);
	}

	/* Make the temporary DBM file */
	cmdbuf = am(myself, strlen("/usr/sbin/makedbm") +
			(strlen(map->map_path) - strlen(map->map_name)) +
			strlen(temp_file_name) +
			strlen(temp_entries) + 3);
	if (NULL == cmdbuf) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Could not allocate cmdbuf.", myself);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	strcpy(cmdbuf, "/usr/sbin/makedbm ");
	strncat(cmdbuf, map->map_path, strlen(map->map_path) -
						strlen(map->map_name));
	strcat(cmdbuf, temp_file_name);
	strcat(cmdbuf, " ");
	strcat(cmdbuf, temp_entries);

	if (0 > system(cmdbuf)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not run \"%s\" "
			"(errno=%d)", myself, cmdbuf, errno);
		sfree(cmdbuf);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	/* Already have enough command buffer to rm temporary file */
	strlcpy(cmdbuf, map->map_path, strlen(map->map_path) -
						strlen(map->map_name) + 1);
	strcat(cmdbuf, temp_file_name);
	res = unlink(cmdbuf);
	/* If the temp file did not exist no problem. Probably had no entries */
	if ((0 != res) && (ENOENT != errno)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not delete \"%s\" "
			"(errno=%d)", myself, cmdbuf, errno);
		sfree(temp_entries);
		sfree(temp_ttl);
		sfree(cmdbuf);
		return (FAILURE);
	}
	sfree(cmdbuf);

	if ((temp_entries_db = dbm_open(temp_entries, O_RDWR | O_CREAT, 0644))
						== NULL) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not open %s",
						myself, temp_entries);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	if ((temp_ttl_db = dbm_open(temp_ttl, O_RDWR | O_CREAT, 0644))
						== NULL) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "%s: Could not open %s",
						myself, temp_ttl);
		dbm_close(temp_entries_db);
		sfree(temp_entries);
		sfree(temp_ttl);
		return (FAILURE);
	}

	/*
	 * Set up enough of map_ctrl to call update_entry_ttl. Since there is
	 * no mapping, and thus not TTL, defined for these maps use the TTL
	 * values for netgroup map
	 */
	temp_map.map_name = NETGROUP_MAP;
	temp_map.domain = map->domain;
	temp_map.ttl = temp_ttl_db;

	/*
	 * Generate new TTL file.  Since these maps work only on the whole map
	 * expiry these will not actually be used but there presence makes it
	 * easier to handle these maps in the same way as other maps.
	 */
	key = dbm_firstkey(temp_entries_db);
	while (key.dptr != 0) {
		if (!is_special_key(&key))
			/*
			 * For these maps want all timouts to be maximum
			 */
			if (FAILURE == update_entry_ttl(&temp_map, &key,
								TTL_MAX))
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Could not update TTL for "
					"(key=%s) for map %s,%s",
					myself, NIL(key.dptr), map->map_name,
					map->domain);
		key = dbm_nextkey(temp_entries_db);
	}

	/* Update map TTL */
	update_map_ttl(&temp_map);

	/* Close temp DBM files */
	dbm_close(temp_entries_db);
	dbm_close(temp_ttl_db);

	/* Lock access to the map for copy */
	lock_map_ctrl(map);

	/* Move temp maps to real ones */
	rename_map(temp_entries, map->map_path, FALSE);
	rename_map(temp_ttl, map->ttl_path, FALSE);

	/* Free file names */
	sfree(temp_entries);
	sfree(temp_ttl);

	/* Unlock map */
	unlock_map_ctrl(map);

	return (SUCCESS);
}
