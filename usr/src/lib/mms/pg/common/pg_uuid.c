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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <postgres.h>
#include <fmgr.h>
#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/uuid.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

/*
 * Postgres server library for MMS UUID.
 */

#define	UUID_POSTGRES_LEN 36

extern void uuid_clear(uuid_t uu);
extern void uuid_generate_random(uuid_t uu);
extern void uuid_unparse(uuid_t uu, char *out);

PG_FUNCTION_INFO_V1(pg_get_uuid);

Datum
pg_get_uuid(PG_FUNCTION_ARGS)
{
	text *pg_uuid;
	int len;
	uuid_t uuid;
	char buf[UUID_POSTGRES_LEN+1];

	len = VARHDRSZ + UUID_POSTGRES_LEN;
	pg_uuid = (text*)palloc(len);
	if (pg_uuid == NULL) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}
	(void) memset(pg_uuid, 0, len);
	VARATT_SIZEP(pg_uuid) = len;

	/* cefa7a9c-1dd2-11b2-8350-880020adbeef */
	uuid_clear(uuid);
	uuid_generate_random(uuid);
	uuid_unparse(uuid, buf);

	/* don't copy string null terminator, pg string struct has length */
	(void) memcpy(VARDATA(pg_uuid), buf, UUID_POSTGRES_LEN);

	PG_RETURN_TEXT_P(pg_uuid);
}
