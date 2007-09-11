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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CACHEMGR_H
#define	_CACHEMGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "cachemgr_door.h"

#define	LOGFILE		"/var/ldap/cachemgr.log"
#define	KILLCACHEMGR	"/var/lib/ldap/ldap_cachemgr -K"
#define	MAXBITSIZE	30
#define	MAXDEBUG	DBG_ALL
#define	DEFAULTTTL	3600		/* 1 hour */

typedef	union {
	ldap_data_t	data;
	char		space[BUFFERSIZE];
} dataunion;

extern char *getcacheopt(char *s);
extern void logit(char *format, ...);
extern int load_admin_defaults(admin_t *ptr, int will_become_server);
extern int getldap_init(void);
extern void getldap_revalidate(void);
extern int getldap_uidkeepalive(int keep, int interval);
extern int getldap_invalidate(void);
extern void getldap_lookup(LineBuf *config_info, ldap_call_t *in);
extern void getldap_refresh(void);
extern int cachemgr_set_dl(admin_t *ptr, int value);
extern int cachemgr_set_ttl(ldap_stat_t *cache, char *name, int value);
extern int get_clearance(int callnumber);
extern int release_clearance(int callnumber);
#ifdef SLP
extern void discover();
#endif /* SLP */
extern void getldap_serverInfo_refresh(void);
extern void getldap_getserver(LineBuf *config_info, ldap_call_t *in);
extern void getldap_get_cacheData(LineBuf *config_info, ldap_call_t *in);
extern int getldap_set_cacheData(ldap_call_t *in);
extern void getldap_get_cacheStat(LineBuf *stat_info);
#ifdef __cplusplus
}
#endif

#endif /* _CACHEMGR_H */
