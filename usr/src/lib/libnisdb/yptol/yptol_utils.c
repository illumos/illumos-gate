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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DESCRIPTION: Contains helper functions for N2L
 */

/*
 * Includes. WE WANT TO USE REAL DBM FUNCTIONS SO DO NOT INCLUDE SHIM_HOOKS.H.
 */
#include <unistd.h>
#include <syslog.h>
#include <ndbm.h>
#include <sys/systeminfo.h>
#include <errno.h>
#include <strings.h>
#include "ypsym.h"
#include "ypdefs.h"
#include "shim.h"
#include "yptol.h"
#include "stdio.h"
#include "../ldap_util.h"

/* Enable standard YP code features defined in ypdefs.h */
USE_YP_PREFIX
USE_YP_MASTER_NAME
USE_YP_LAST_MODIFIED
USE_YP_INPUT_FILE
USE_YP_OUTPUT_NAME
USE_YP_DOMAIN_NAME
USE_YP_SECURE
USE_YP_INTERDOMAIN
USE_DBM

/*
 * FUNCTION :	alloc_temp_names()
 *
 * DESCRIPTION:	Creates the set of temporary names for update files. It is
 *		the caller responsibility to free these.
 *
 * GIVEN :	Name of map (fully qualified)
 *
 * RETURNS :	SUCCESS with all names allocated.
 *		FAILURE with no names allocated.
 */
suc_code
alloc_temp_names(char *name, char **temp_entries, char **temp_ttl)
{
	char *myself = "alloc_temp_names";

	*temp_entries = (char *)am(myself, strlen(name) +
						strlen(TEMP_POSTFIX) + 1);
	if (NULL == *temp_entries) {
		return (FAILURE);
	}

	*temp_ttl = (char *)am(myself, strlen(TEMP_POSTFIX) + strlen(name) +
						strlen(TTL_POSTFIX) + 1);
	if (NULL == *temp_ttl) {
		sfree(*temp_entries);
		return (FAILURE);
	}

	strcpy(*temp_entries, name);
	strcat(*temp_entries, TEMP_POSTFIX);

	strcpy(*temp_ttl, name);
	strcat(*temp_ttl, TTL_POSTFIX);
	strcat(*temp_ttl, TEMP_POSTFIX);

	return (SUCCESS);
}

/*
 * FUNCTION :	addpair()
 *
 * DESCRIPTION:	Adds a single string entry to a dbm database. This is a copy of
 *		a function from makedbm but is useful enough to be put into
 *		shared code.
 *
 * GIVEN:	Database handle
 *		Key
 *		Value
 *
 * RETURNS :	SUCCESS = Value written
 *		FAILURE = Value not written.
 */
suc_code
addpair(DBM *fdb, char *str1, char *str2)
{
	datum key;
	datum content;

	key.dptr = str1;
	key.dsize = strlen(str1);
	content.dptr  = str2;
	content.dsize = strlen(str2);
	errno = 0;
	if (dbm_store(fdb, key, content, DBM_REPLACE) != 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Problem storing %.*s %.*s "
					"(errno=%d)",
					key.dptr, content.dptr, errno);
		return (FAILURE);
	}
	return (SUCCESS);
}

/*
 * FUNCTION :	dump_datum()
 *
 * DESCRIPTION:	Prints out a datum as a text string with no line feed.
 */
void
dump_datum(datum *dat)
{
	int	i;

	if (NULL == dat) {
		printf("NULL datum");
		return;
	}

	if (NULL == dat->dptr) {
		printf("NULL dptr");
		return;
	}
	for (i = 0; i < dat->dsize; i++)
		putchar(dat->dptr[i]);
}

/*
 * FUNCTION :	update_timestamp()
 *
 * DESCRIPTION:	Adds, or updates, a maps last modified timestamp.
 *
 * GIVEN :	Pointer to an open DBM file.
 *
 * RETURNS :	SUCCESS = Entry created
 *		FAILURE = Entry not created
 */
suc_code
update_timestamp(DBM *db)
{
	char time_string[MAX_ASCII_ORDER_NUMBER_LENGTH];
	struct timeval	now;

	if (0 != gettimeofday(&now, NULL)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Could not get time of day");
		return (FAILURE);
	}
	sprintf(time_string, "%010ld", (long)now.tv_sec);
	if (SUCCESS != addpair(db, yp_last_modified, time_string))
		return (FAILURE);

	return (SUCCESS);
}
