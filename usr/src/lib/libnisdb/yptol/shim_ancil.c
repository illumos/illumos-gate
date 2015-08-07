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
 * Copyright 2015 Gary Mills
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdlib.h>
#include <dirent.h>
#include <strings.h>
#include "ypsym.h"
#include "ypdefs.h"
USE_YPDBPATH
USE_DBM
#include "shim.h"
#include "../ldap_util.h"

/*
 * This constructs a file name from a passed domain name, a passed map name,
 * and a globally known YP data base path prefix.
 *
 * Has to be in shim because it needs the N2L prefix
 *
 * RETURNS :	TRUE = A name was successfully created
 *		FALSE = A name could not be created
 */

bool_t
ypmkfilename(domain, map, path)
	char *domain;
	char *map;
	char *path;
{
	int length;

	/* Do not allow any path as a domain name. */
	if (strchr(domain, '/') != NULL)
		return (FALSE);

	length = strlen(domain) + strlen(map) + ypdbpath_sz + 3;
	if (yptol_mode)
		length += strlen(NTOL_PREFIX) + 1;

	if ((MAXNAMLEN + 1) < length) {
		(void) fprintf(stderr, "ypserv:  Map name string too long.\n");
		return (FALSE);
	}

	strcpy(path, ypdbpath);
	strcat(path, "/");
	strcat(path, domain);
	strcat(path, "/");

	/* If in N2L mode add N2L prefix */
	if (yptol_mode)
		strcat(path, NTOL_PREFIX);
	strcat(path, map);

	return (TRUE);
}

/*
 * check whether a map is already in an array/list
 *
 * RETURNS: TRUE if yes
 *          FALSE if not
 */
bool_t
on_maplist(char *mapname, char **list) {
	int i = 0;

	if (list == NULL) {
		return (FALSE);
	}

	while (list[i] != NULL) {
		if (strcmp(mapname, list[i++]) == 0) {
			return (TRUE);
		}
	}

	return (FALSE);
}

/*
 * add a map at the end of an array/list
 *
 * list_len: if -1, we do not know list length
 *
 * RETURNS: TRUE if map was added
 *          FALSE if not
 */
bool_t
add_in_maplist(char *mapname, char ***list, int *list_len) {
	int i = 0;
	char **list_tmp;

	if (list == NULL) {
		return (FALSE);
	}

	list_tmp = *list;

	if (list_tmp == NULL) {
		*list_len = 0;
	} else {
		/* find 1st free element */
		while (list_tmp[i] != NULL) {
			/*
			 * increment in loop so that
			 * list_tmp[i] == NULL
			 * when exiting
			 */
			i++;
		}
	}

	/* if we don't know list length, assume we reach its end */
	if (*list_len == -1) {
		*list_len = i;
	}

	/* do we need to reallocate ? */
	if (i+1 >= *list_len) {
		list_tmp = (char **)realloc(list_tmp,
				    (*list_len + ARRAY_CHUNK) *
					sizeof (char *));
		if (list_tmp == NULL) {
			return (FALSE);
		}
		*list = list_tmp;
		*list_len += ARRAY_CHUNK;
	}

	/* add in list */
	(*list)[i] = strdup(mapname);
	if ((*list)[i] == NULL) {
		/* strdup() failed */
		return (FALSE);
	}
	(*list)[++i] = NULL;

	return (TRUE);
}

/*
 * This checks to see whether a domain name is present at the local node as a
 * subdirectory of ypdbpath
 *
 * Was originally in cmd/ypcmd/shared/ancil.c as ypcheck_domain(domain).
 * Now ypcheck_domain(domain) calls this function.
 */
bool
ypcheck_domain_yptol(char *domain)
{
	char path[MAXNAMLEN + 1];
	struct stat filestat;
	bool present = FALSE;

	strcpy(path, ypdbpath);
	strcat(path, "/");
	if (strlcat(path, domain, MAXNAMLEN + 1) >=  MAXNAMLEN + 1)
		return (present);

	if (stat(path, &filestat) != -1) {
		if (S_ISDIR(filestat.st_mode))
			present = TRUE;
	}
	return (present);
}

/*
 * This performs an existence check on the dbm data base files <name>.pag and
 * <name>.dir.  pname is a ptr to the filename.  This should be an absolute
 * path.
 * Returns TRUE if the map exists and is accessible; else FALSE.
 *
 * Note:  The file name should be a "base" form, without a file "extension" of
 * .dir or .pag appended.  See ypmkfilename for a function which will generate
 * the name correctly.  Errors in the stat call will be reported at this level,
 * however, the non-existence of a file is not considered an error, and so will
 * not be reported.
 *
 * Was originally in cmd/ypcmd/shared/utils.c as ypcheck_map_existence().
 * Now ypcheck_map_existence() calls this function.
 */
bool
ypcheck_map_existence_yptol(char *pname)
{
	char dbfile[MAXNAMLEN + sizeof (TTL_POSTFIX) + 1];
	struct stat64 filestat;
	int len;

	if (!pname || ((len = (int)strlen(pname)) == 0) ||
	    (len + sizeof (dbm_pag) + sizeof (TTL_POSTFIX)) >
	    sizeof (dbfile)) {
		return (FALSE);
	}

	errno = 0;

	/* Check for existance of .dir file */
	(void) strcpy(dbfile, pname);
	(void) strcat(dbfile, dbm_dir);

	if (stat64(dbfile, &filestat) == -1) {
		if (errno != ENOENT) {
			(void) fprintf(stderr,
			    "ypserv:  Stat error on map file %s.\n",
			    dbfile);
		}
		return (FALSE);
	}

	/* Check for existance of .pag file */
	(void) strcpy(dbfile, pname);
	(void) strcat(dbfile, dbm_pag);

	if (stat64(dbfile, &filestat) == -1) {
		if (errno != ENOENT) {
			(void) fprintf(stderr,
			    "ypserv:  Stat error on map file %s.\n",
			    dbfile);
		}
		return (FALSE);
	}

	if (yptol_mode) {
		/* Check for existance of TTL .dir file */
		(void) strcpy(dbfile, pname);
		(void) strcat(dbfile, TTL_POSTFIX);
		(void) strcat(dbfile, dbm_dir);

		if (stat64(dbfile, &filestat) == -1) {
			if (errno != ENOENT) {
				(void) fprintf(stderr,
				    "ypserv:  Stat error on map file %s.\n",
				    dbfile);
			}
			return (FALSE);
		}

		/* Check for existance of TTL .pag file */
		(void) strcpy(dbfile, pname);
		(void) strcat(dbfile, TTL_POSTFIX);
		(void) strcat(dbfile, dbm_pag);

		if (stat64(dbfile, &filestat) == -1) {
			if (errno != ENOENT) {
				(void) fprintf(stderr,
				    "ypserv:  Stat error on map file %s.\n",
				    dbfile);
			}
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 * This adds maps in a domain to a given list,
 * from maps in /var/yp/<domain>
 * Inspired from yplist_maps() in cmd/ypcmd/ypserv_ancil.c
 *
 * domain is the relevant domain name
 * map_list is the list of maps in an array of map names,
 *    which may or may not be empty
 *
 * RETURNS :    TRUE = everything went fine
 *              FALSE = an error occured
 */
bool_t
add_map_domain_to_list(char *domain, char ***map_list)
{
	char domdir[MAXNAMLEN + 1];
	char path[MAXNAMLEN + 1];
	int domdir_len = sizeof (domdir);
	DIR *dirp;
	struct dirent *dp;
	int name_len;
	int dbm_pag_len = sizeof (dbm_pag);
	char *ext;
	char *mapname;
	int map_list_len = -1;

	if (map_list == NULL) {
		return (FALSE);
	}

	/* no domain, not a problem */
	if (domain == NULL) {
		return (TRUE);
	}

	/* not a valid domain, not a problem */
	if (!ypcheck_domain_yptol(domain)) {
		return (TRUE);
	}

	if (snprintf(domdir, domdir_len, "%s/%s", ypdbpath, domain)
	    > domdir_len) {
		return (FALSE);
	}

	if ((dirp = opendir(domdir)) == NULL) {
		return (FALSE);
	}

	for (dp = readdir(dirp); dp != NULL;
	    dp = readdir(dirp)) {
		/*
		 * If it's possible that the file name is one of the two files
		 * implementing a map, remove the extension (dbm_pag or dbm_dir)
		 */
		name_len = (int)strlen(dp->d_name);

		if (name_len < dbm_pag_len - 1) {
			continue;		/* Too Short */
		}

		ext = &(dp->d_name[name_len - (dbm_pag_len - 1)]);

		if (strcmp(ext, dbm_pag) != 0) {
			continue;		/* No dbm file extension */
		}

		*ext = '\0';

		/*
		 * In yptol mode look at LDAP_ prefixed maps. In non yptol mode
		 * ignore them.
		 */
		if (yptol_mode) {
			if (0 != strncmp(dp->d_name, NTOL_PREFIX,
			    strlen(NTOL_PREFIX))) {
				continue;
			}

			/*
			 * Already have an LDAP_ prefix. Don't want to add it
			 * twice.
			 */
			mapname = dp->d_name + strlen(NTOL_PREFIX);
		} else {
			if (0 == strncmp(dp->d_name, NTOL_PREFIX,
			    strlen(NTOL_PREFIX))) {
				continue;
			}
			mapname = dp->d_name;
		}

		if (ypmkfilename(domain, mapname, path) == FALSE) {
			(void) closedir(dirp);
			return (FALSE);
		}

		/*
		 * At this point, path holds the map file base name (no dbm
		 * file extension), and mapname holds the map name.
		 */
		if (ypcheck_map_existence_yptol(path) &&
		    !on_maplist(mapname, *map_list)) {
			if (add_in_maplist(mapname, map_list, &map_list_len) ==
			    FALSE) {
				(void) closedir(dirp);
				return (FALSE);
			}
		}
	}

	(void) closedir(dirp);
	return (TRUE);
}
