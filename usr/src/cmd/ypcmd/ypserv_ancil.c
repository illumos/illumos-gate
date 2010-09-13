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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	lint
static	char sccsid[] = "@(#)ypserv_ancil.c 1.13 88/02/08 Copyr 1984 Sun Micro";
#endif

#include <dirent.h>
#include <syslog.h>
#include "ypsym.h"
#include "ypdefs.h"
USE_YPDBPATH
USE_DBM
#include "shim_hooks.h"
#include "shim.h"
#include "yptol.h"

extern unsigned int strlen();
extern int strcmp();
extern int isvar_sysv();
extern char *strncpy();
extern int yp_getkey();

/*
 * This generates a list of the maps in a domain.
 */
int
yplist_maps(domain, list)
	char *domain;
	struct ypmaplist **list;
{
	DIR *dirp;
	struct dirent *dp;
	char domdir[MAXNAMLEN + 1];
	char path[MAXNAMLEN + 1];
	char map_key[YPMAXMAP + 1];
	int error;
	char *ext;
	struct ypmaplist *map;
	int namesz;
	char *mapname;

	*list = (struct ypmaplist *)NULL;

	if (!ypcheck_domain(domain)) {
		return (YP_NODOM);
	}

	(void) strcpy(domdir, ypdbpath);
	(void) strcat(domdir, "/");
	(void) strcat(domdir, domain);

	if ((dirp = opendir(domdir)) == NULL) {
		return (YP_YPERR);
	}

	error = YP_TRUE;

	for (dp = readdir(dirp); error == YP_TRUE && dp != NULL;
	    dp = readdir(dirp)) {
		/*
		 * If it's possible that the file name is one of the two files
		 * implementing a map, remove the extension (dbm_pag or dbm_dir)
		 */
		namesz =  (int)strlen(dp->d_name);

		if (namesz < sizeof (dbm_pag) - 1)
			continue;		/* Too Short */

		ext = &(dp->d_name[namesz - (sizeof (dbm_pag) - 1)]);

		if (strcmp(ext, dbm_pag) != 0)
			continue;		/* No dbm file extension */

		*ext = '\0';


		/*
		 * In yptol mode look at LDAP_ prefixed maps. In non yptol mode
		 * ignore them.
		 */
		if (yptol_mode) {
			if (0 != strncmp(dp->d_name, NTOL_PREFIX,
							strlen(NTOL_PREFIX)))
				continue;

			/*
			 * Already have an LDAP_ prefix. Don't want to add it
			 * twice.
			 */
			mapname = dp->d_name + strlen(NTOL_PREFIX);
		} else {
			if (0 == strncmp(dp->d_name, NTOL_PREFIX,
							strlen(NTOL_PREFIX)))
				continue;
			mapname = dp->d_name;
		}

		ypmkfilename(domain, mapname, path);

		/*
		 * At this point, path holds the map file base name (no dbm
		 * file extension), and mapname holds the map name.
		 */
		if (ypcheck_map_existence(path) &&
		    !onmaplist(mapname, *list)) {

			if ((map = (struct ypmaplist *)malloc(
			    sizeof (struct ypmaplist))) == NULL) {
				error = YP_YPERR;
				break;
			}

			map->ypml_next = *list;
			*list = map;
			namesz = (int)strlen(mapname);

			if (namesz <= YPMAXMAP) {
				if (yp_getkey(mapname, map_key,
						MAXALIASLEN) < 0) {

					fprintf(stderr,
					"yplist_maps: getkey failed for %s\n",
						mapname);
					error = YP_YPERR;
					break;
				} else
					(void) strcpy(map->ypml_name, map_key);
			} else {
				if (yp_getkey(mapname, map_key,
						MAXALIASLEN) < 0) {
					fprintf(stderr,
					"yplist_maps: getkey failed for %s\n",
						mapname);
					error = YP_YPERR;
					break;
				} else if (strcmp(mapname, map_key) == 0) {
					(void) strncpy(map->ypml_name,
							mapname,
							(unsigned int) namesz);
					map->ypml_name[YPMAXMAP] = '\0';
				} else {
					(void) strcpy(map->ypml_name, map_key);
				}
			}
		}
	}

	closedir(dirp);
	return (error);
}
