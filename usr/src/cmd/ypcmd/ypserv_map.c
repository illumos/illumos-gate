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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <malloc.h>
#include "ypsym.h"
#include "ypdefs.h"

/* Use N2L version of DBM calls */
#include "shim_hooks.h"

USE_YP_MASTER_NAME
USE_YP_LAST_MODIFIED
USE_YPDBPATH
USE_YP_SECURE
USE_DBM

#include <ctype.h>

static DBM *cur_fdb; /* will be passwd back up by ypset_current_map */
static enum { UNKNOWN, SECURE, PUBLIC } current_map_access = UNKNOWN;
static char map_owner[MAX_MASTER_NAME + 1];

extern unsigned int ypcheck_domain();
int check_secure_net_ti(struct netbuf *caller, char *ypname);

/*
 * The retrieves the order number of a named map from the order number datum
 * in the map data base.
 */
bool
ypget_map_order(char *map, char *domain, uint_t *order)
{
	datum key;
	datum val;
	char toconvert[MAX_ASCII_ORDER_NUMBER_LENGTH + 1];
	uint_t error;
	DBM *fdb;

	if ((fdb = ypset_current_map(map, domain, &error)) != NULL) {
		key.dptr = yp_last_modified;
		key.dsize = yp_last_modified_sz;
		val = dbm_fetch(fdb, key);

		if (val.dptr != (char *)NULL) {

			if (val.dsize > MAX_ASCII_ORDER_NUMBER_LENGTH) {
			return (FALSE);
			}

			/*
			 * This is getting recopied here because val.dptr
			 * points to static memory owned by the dbm package,
			 * and we have no idea whether numeric characters
			 * follow the order number characters, nor whether
			 * the mess is null-terminated at all.
			 */

			memcpy(toconvert, val.dptr, val.dsize);
			toconvert[val.dsize] = '\0';
			*order = (unsigned long) atol(toconvert);
			return (TRUE);
		} else {
			return (FALSE);
		}

	} else {
		return (FALSE);
	}
}

/*
 * The retrieves the master server name of a named map from the master datum
 * in the map data base.
 */
bool
ypget_map_master(char **owner, DBM *fdb)
{
	datum key;
	datum val;

	key.dptr = yp_master_name;
	key.dsize = yp_master_name_sz;
	val = dbm_fetch(fdb, key);

	if (val.dptr != (char *)NULL) {

		if (val.dsize > MAX_MASTER_NAME) {
			return (FALSE);
		}

		/*
		 * This is getting recopied here because val.dptr
		 * points to static memory owned by the dbm package.
		 */
		memcpy(map_owner, val.dptr, val.dsize);
		map_owner[val.dsize] = '\0';
		*owner = map_owner;
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 * This makes a map into the current map, and calls dbminit on that map
 * and returns the DBM pointer to the map. Procedures called by
 * ypserv dispatch routine would use this pointer for successive
 * ndbm operations.  Returns an YP_xxxx error code in error if FALSE.
 */
DBM *
ypset_current_map(char *map, char *domain, uint_t *error)
{
	char mapname[MAXNAMLEN + 1];
	int lenm, lend;

	/* Do not allow any path as a domain name or a map name.   */
	if (!map || ((lenm = (int)strlen(map)) == 0) || (lenm > YPMAXMAP) ||
	    !domain || ((lend = (int)strlen(domain)) == 0) ||
	    (lend > YPMAXDOMAIN) || (strchr(map, '/') != NULL) ||
	    (strchr(domain, '/') != NULL)) {
		*error = YP_BADARGS;
		return (FALSE);
	}

	if (FALSE == ypmkfilename(domain, map, mapname))
		return (FALSE);

	if ((cur_fdb) && (strcmp(mapname, get_map_name(cur_fdb)) == 0)) {
		return (cur_fdb);
	}

	/* If there was a previous open map close it */
	if (NULL != cur_fdb)
		dbm_close(cur_fdb);

	/* Set the map access as "unknown" as the new map has not been loaded */
	current_map_access = UNKNOWN;

	/* All the map locking is now handled inside the dbm_open shim */
	if ((cur_fdb = dbm_open(mapname, O_RDWR, 0644)) != NULL) {
		return (cur_fdb);
	}

	if (ypcheck_domain(domain)) {

		if (ypcheck_map_existence(mapname)) {
			*error = YP_BADDB;
		} else {
			*error = YP_NOMAP;
		}

	} else {
		*error = YP_NODOM;
	}

	return (NULL);
}

/*
 * This checks to see if there is a current map, and, if there is, does a
 * dbmclose on it and sets the current map name and its DBM ptr to null.
 */
void
ypclr_current_map(void)
{
	if (cur_fdb != NULL) {
		(void) dbm_close(cur_fdb);
		cur_fdb = NULL;
	}
	current_map_access = UNKNOWN;
}

/*
 * Checks to see if caller has permission to query the current map (as
 * set by ypset_current_map()).  Returns TRUE if access is granted and
 * FALSE otherwise.  If FALSE then sets *error to YP_xxxxxxxx.
 */
bool
yp_map_access(SVCXPRT *transp, uint_t *error, DBM *fdb)
{
	char *ypname = "ypserv";
	struct netbuf *nbuf;
	sa_family_t af;
	in_port_t port;

	nbuf = svc_getrpccaller(transp);
	af = ((struct sockaddr_storage *)nbuf->buf)->ss_family;
	if (af != AF_INET && af != AF_INET6)
		return (FALSE);

	if (!(check_secure_net_ti(nbuf, ypname))) {
		*error = YP_NOMAP;
		return (FALSE);
	}

	/* XXX - I expect that this won't happen much */
	if (current_map_access == PUBLIC) {
		return (TRUE);
	}

	if (af == AF_INET6) {
		port = ntohs(((struct sockaddr_in6 *)nbuf->buf)->sin6_port);
	} else {
		port = ntohs(((struct sockaddr_in *)nbuf->buf)->sin_port);
	}
	if (port < IPPORT_RESERVED) {
		return (TRUE);
	}

	if (current_map_access == UNKNOWN) {
		datum key;
		datum val;

		key.dptr = yp_secure;
		key.dsize = yp_secure_sz;
		val = dbm_fetch(fdb, key);
		if (val.dptr == (char *)NULL) {
			current_map_access = PUBLIC;
			return (TRUE);
		}
		current_map_access = SECURE;
	}

	/* current_map_access == SECURE and non-priviledged caller */
	*error = YP_NOMAP;
	return (FALSE);
}
