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
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * gsscred utility
 *
 * Manages mapping between a security principal
 * name and unix uid.
 */

#ifndef	_GSSCRED_H
#define	_GSSCRED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <locale.h>
#include <gssapi/gssapi.h>
#include <pwd.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#define	GSSCRED_FLAT_FILE	-1

/* Structure to hold GSS credentials for each entry */
typedef struct GssCredEntry_t {
	char *principal_name;
	int  unix_uid;
	char *comment;
	struct GssCredEntry_t *next;
} GssCredEntry;

/*
 * Misc functions in gsscred.
 */
int gsscred_AsHex(const gss_buffer_t inBuf, gss_buffer_t outBuf);
int gsscred_MakeName(const gss_OID mechOid, const char *name,
		const char *nameOid, gss_buffer_t OutName);
int gsscred_read_config_file(void);
int gsscred_MakeNameHeader(const gss_OID mechOid, gss_buffer_t outNameHdr);


/*
 * Flat file based gsscred functions.
 */
int file_addGssCredEntry(const gss_buffer_t hexName, const char *uid,
	const char *comment, char **errDetails);
int file_getGssCredEntry(const gss_buffer_t name, const char *uid,
	char **errDetails);
int file_deleteGssCredEntry(const gss_buffer_t name, const char *uid,
	char **errDetails);
int file_getGssCredUid(const gss_buffer_t name, uid_t *uidOut);


/*
 * GSS entry point for retrieving user uid information based on
 * exported name buffer.
 */
int gss_getGssCredEntry(const gss_buffer_t expName, uid_t *uid);

#ifdef	__cplusplus
}
#endif

#endif	/* _GSSCRED_H */
