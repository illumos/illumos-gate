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
 * Copyright 2015 Gary Mills
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains functions relating to movement of entire maps.
 */

#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <string.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

/*
 * Switch on parts of ypdefs.h
 */
USE_YPDBPATH

/*
 * Decs
 */
void add_separator(char *);
suc_code dump_domain_to_dit(char *, bool_t);
suc_code dump_map_to_dit(char *, char *, bool_t);
suc_code dump_maps_to_dit(bool_t);
suc_code dump_dit_to_map();
suc_code dump_dit_to_maps();

/*
 * FUNCTION :	dump_maps_to_dit()
 *
 * DESCRIPTION:	Dump all the OLD STYLE NIS maps into the DIT.
 *
 *		Since the DIT is not yet set up details about which maps and
 *		domains exist are gathered from the N2L config file and the
 *		existing map files.
 *
 * GIVEN :	Flag indicating if containers and domains should be set up.
 *
 * RETURNS :	Success code
 */
suc_code
dump_maps_to_dit(bool_t init_containers)
{
	char **dom_list;
	int num_doms, i;

	num_doms = get_mapping_domain_list(&dom_list);

	/* Dump all domains in list */
	for (i = 0; i < num_doms; i++) {
		if (FAILURE == dump_domain_to_dit(dom_list[i], init_containers))
			return (FAILURE);
	}

	return (SUCCESS);
}

/*
 * FUNCTION :	dump_domain_to_dit()
 *
 * DESCRIPTION:	Dumps all maps in one domain into the DIT
 *
 * GIVEN :	Name of the domain
 *		Flag indicating if containers and domains should be set up.
 *
 * RETURNS :	SUCCESS = domain completely dumped
 *		FAILURE = domain not completely dumped
 *
 */
suc_code
dump_domain_to_dit(char *dom_name, bool_t init_containers)
{
	char **map_list;
	int	i;

	/* Set up nis domain object */
	if (SUCCESS != make_nis_domain(dom_name, init_containers)) {
		if (init_containers)
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Could not make nisDomain object for %s", dom_name);
		else
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Problem detected with nisDomain object for %s",
								dom_name);
		return (FAILURE);
	}

	/* Get list of maps from mapping file */
	map_list = get_mapping_map_list(dom_name);
	if (NULL == map_list) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Could not get map list for %s", dom_name);
		return (FAILURE);
	}

	for (i = 0; NULL != map_list[i]; i++) {
		dump_map_to_dit(map_list[i], dom_name, init_containers);
	}

	free_map_list(map_list);

	return (SUCCESS);
}

/*
 * FUNCTION :	dump_map_to_dit()
 *
 * DESCRIPTION:	Dump a OLD STYLE NIS map into the DIT.
 *
 * GIVEN :	Name of map (not fully qualified)
 *		Name of domain
 *		Flag indicating if containers should be set up.
 *
 * RETURNS :	SUCCESS = Map copy completed
 *		FAILURE = Map copy not completed
 */
suc_code
dump_map_to_dit(char *map_name, char *domain, bool_t init_containers)
{
	char *myself = "dump_map_to_dit";
	DBM *dbm;
	datum key;
	datum value;
	char *map_path;		/* Qualified map name */
	int entry_count;
	int next_print;

	printf("Copying map \"%s\", domain \"%s\", to LDAP.\n",
							map_name, domain);

	/* Create the NIS container */
	if (SUCCESS != make_nis_container(map_name, domain, init_containers)) {
		if (init_containers)
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not make container for %s %s",
				map_name, domain);
		else
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Problem detected with container for %s %s",
				map_name, domain);

		return (FAILURE);
	}

	/* Make up fully qualified map name */
	map_path = (char *)am(myself, strlen(domain) + strlen(map_name) +
						ypdbpath_sz + 3);
	if (NULL == map_path) {
		logmsg(MSG_NOMEM, LOG_ERR,
			"Could not alloc memory for %s %s", map_name, domain);
		return (FAILURE);
	}
	strcpy(map_path, ypdbpath);
	add_separator(map_path);
	strcat(map_path, domain);
	add_separator(map_path);
	strcat(map_path, map_name);

	/* Open the DBM file. Use real dbm call */
	dbm = dbm_open(map_path, O_RDONLY, 0644);

	/* Finished with full name */
	sfree(map_path);

	if (NULL == dbm) {
		/*
		 * This map probably didn't exist. No problem, user may be
		 * going to populate container using LDAP.
		 */
		return (SUCCESS);
	}

	/*
	 * N2L has no lock for old style maps. No problem ypserv -i is the
	 * only thing that accesses them.
	 */

	/* For all entries in file */
	for (key = dbm_firstkey(dbm), next_print = PRINT_FREQ, entry_count = 1;
		NULL != key.dptr; key = dbm_nextkey(dbm), entry_count ++) {

		/* Don't write zero length keys */
		if (0 == key.dsize) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"Zero length key ignored in %s %s", map_name, domain);
			continue;
		}

		/* Don't write 'special' nis entries */
		if (is_special_key(&key))
			continue;

		/* Get entry */
		value = dbm_fetch(dbm, key);

		/* Copy entry to DIT */
		if (SUCCESS != write_to_dit(map_name, domain, key, value,
								TRUE, TRUE))
			/* Syslog will have already been done */
			break;

		/* If necessary print a progress report */
		if (entry_count >= next_print) {
			printf("%d entries processed.\n", entry_count);
			next_print *= 2;
		}
	}

	dbm_close(dbm);

	return (SUCCESS);
}

/*
 * FUNCTION :	dump_dit_to_maps()
 *
 * DESCRIPTION:	Dumps the contents of the DIT into the NEW STYLE NIS maps. If
 *		the maps, or their TTL files do not exist creates them.
 *
 *		Since we are now treating the DIT as authoritative details of
 *		which domains and maps exist are gathered from the DIT.
 *
 * GIVEN :	Nothing
 *
 * RETURNS :	Success code
 */
suc_code
dump_dit_to_maps()
{
	char **dom_list;
	int dom_count;
	char *dom_path;
	char **map_list;
	int i, j;
	char *myself = "dump_dit_to_maps";

	/* For all domain objects in DIT */
	dom_count = get_mapping_domain_list(&dom_list);

	if (0 == dom_count) {
		/* No problem, maybe no domains */
		return (SUCCESS);
	}

	/* Dump all domains in list */
	for (i = 0; i < dom_count; i++) {

		/* If necessary create domain directory */
		dom_path = (char *)am(myself, ypdbpath_sz +
						strlen(dom_list[i]) + 2);
		if (NULL == dom_path) {
			return (FAILURE);
		}

		strcpy(dom_path, ypdbpath);
		strcat(dom_path, "/");
		strcat(dom_path, dom_list[i]);

		if (0 != mkdir(dom_path, 0644)) {
			/* If dir exists fine. Just use it */
			if (EEXIST != errno) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not make create domain directory %s",
								dom_path);
				sfree(dom_path);
			}
		}

		sfree(dom_path);

		/* Get list of maps for this domain */
		map_list = get_mapping_map_list(dom_list[i]);
		if (NULL == map_list) {
			/* No problem. Just no maps in this domain */
			continue;
		}

		/* For all maps in domain */
		for (j = 0; map_list[j] != NULL; j++) {
			/* A normal map update will initialize it. */
			if (FAILURE == dump_dit_to_map(map_list[j],
							dom_list[i])) {
				free_map_list(map_list);
				return (FAILURE);
			}

			/* If we have a netgroup also generate netgroup.byxxx */
			if (0 == strcmp(map_list[j], NETGROUP_MAP)) {
				if (FAILURE == dump_dit_to_map(NETGROUP_BYHOST,
								dom_list[i])) {
					free_map_list(map_list);
					return (FAILURE);
				}
				if (FAILURE == dump_dit_to_map(NETGROUP_BYUSER,
								dom_list[i])) {
					free_map_list(map_list);
					return (FAILURE);
				}
			}
		}
		free_map_list(map_list);
	}
	return (SUCCESS);
}

/*
 * FUNCTION :	dump_dit_to_map()
 *
 * DESCRIPTION:	Dumps the contents of the DIT into one NEW STYLE NIS map. If
 *		the map, or its TTL file does not exist creates them.
 *
 *		This is the same operation as is carried out when updating a
 *		map that has timed out. As a result we can call the normal
 *		update function.
 *
 *
 * GIVEN :	Map name (unqualified)
 *		Domain name.
 *
 * RETURNS :	SUCCESS = Map copy complete
 *		FAILURE = Problems
 */
suc_code
dump_dit_to_map(char *map_name, char *domain)
{
	char *myself = "dump_dit_to_map";
	map_ctrl map;
	char 	*map_path;

	printf("Copying LDAP data to map \"%s\", domain \"%s\".\n",
							map_name, domain);

	/*
	 * To call update_map_from_dit() we need an initialized map_ctrl.
	 * The easiest way to get this is to generate a full path to the new
	 * map and then call map_ctrl_init().
	 */
	map_path = (char *)am(myself, ypdbpath_sz + strlen(map_name) +
				strlen(domain) + strlen(NTOL_PREFIX) + 3);
	if (NULL == map_path)
		return (FAILURE);

	strcpy(map_path, ypdbpath);
	add_separator(map_path);
	strcat(map_path, domain);
	add_separator(map_path);
	strcat(map_path, NTOL_PREFIX);
	strcat(map_path, map_name);

	if (FAILURE == map_ctrl_init(&map, map_path)) {
		sfree(map_path);
		return (FAILURE);
	}

	sfree(map_path);

	/*
	 * This is called before anything else is running so don't need to
	 * do normal update lock.
	 */
	return (update_map_from_dit(&map, TRUE));
}

/*
 * FUNCTION :	add_seperator()
 *
 * DESCRIPTION:	Adds a file separator to a string (which must already be big
 *		enough.)
 *
 * GIVEN :	Pointer to the string
 *
 * RETURNS :	Nothing
 */
void
add_separator(char *str)
{
	char *p;

	p = str + strlen(str);
	*p = SEP_CHAR;
	*(p+1) = '\0';
}
