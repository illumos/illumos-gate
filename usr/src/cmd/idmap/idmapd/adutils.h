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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ADUTILS_H
#define	_ADUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Processes name2sid & sid2name lookups for a given user or computer
 * from an AD Difrectory server using GSSAPI authentication
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lber.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <thread.h>
#include <synch.h>
#include "idmap_prot.h"
#include <sys/idmap.h>

/*
 * idmapd interfaces stolen? from other idmapd code?
 */

/*
 * Eventually these should be an enum here, but instead we share a
 * namespace with other things in idmapd.
 */
#define	_IDMAP_T_OTHER		0
#define	_IDMAP_T_UNDEF		-1
#define	_IDMAP_T_USER		-1004
#define	_IDMAP_T_GROUP		-1005
#define	_IDMAP_T_DOMAIN		-1006
#define	_IDMAP_T_COMPUTER	-1007

#define	SID_MAX_SUB_AUTHORITIES	15
#define	MAXBINSID	(1 + 1 + 6 + (SID_MAX_SUB_AUTHORITIES * 4))
#define	MAXHEXBINSID	(MAXBINSID * 3)

typedef uint32_t rid_t;

/*
 * We use the port numbers for normal LDAP and global catalog LDAP as
 * the enum values for this enumeration.  Clever?  Silly?  You decide.
 * Although we never actually use these enum values as port numbers and
 * never will, so this is just cute.
 */
typedef enum idmap_ad_partition {
	IDMAP_AD_DATA = 389,
	IDMAP_AD_GLOBAL_CATALOG = 3268
} idmap_ad_partition_t;

typedef struct ad ad_t;
typedef struct idmap_query_state idmap_query_state_t;

/*
 * Idmap interfaces:
 *
 *  - an ad_t represents an AD partition
 *  - a DS (hostname + port, if port != 0) can be added/removed from an ad_t
 *  - and because libldap supports space-separated lists of servers, a
 *  single hostname value can actually be a set of hostnames.
 *  - an ad_t can be allocated, ref'ed and released; last release
 *  releases resources
 *
 *  - lookups are batched; see below.
 *
 * See below.
 */

/* Allocate/release ad_t objects */
int idmap_ad_alloc(ad_t **new_ad, const char *default_domain,
		idmap_ad_partition_t part);
void idmap_ad_free(ad_t **ad);

/* Add/remove a DS to/from an ad_t */
int idmap_add_ds(ad_t *ad, const char *host, int port);
void idmap_delete_ds(ad_t *ad, const char *host, int port);

/*
 * Batch lookups
 *
 * Start a batch, add queries to the batch one by one (the output
 * pointers should all differ, so that a query's results don't clobber
 * any other's), end the batch to wait for replies for all outstanding
 * queries.  The output parameters of each query are initialized to NULL
 * or -1 as appropriate.
 *
 * LDAP searches are sent one by one without waiting (i.e., blocking)
 * for replies.  Replies are handled as soon as they are available.
 * Missing replies are waited for only when idmap_lookup_batch_end() is
 * called.
 *
 * If an add1 function returns != 0 then abort the batch by calling
 * idmap_lookup_batch_end(), but note that some queries may have been
 * answered, so check the result code of each query.
 */

/* Start a batch of lookups */
idmap_retcode idmap_lookup_batch_start(ad_t *ad, int nqueries,
		idmap_query_state_t **state);

/* End a batch and release its idmap_query_state_t object */
idmap_retcode idmap_lookup_batch_end(idmap_query_state_t **state);

/* Abandon a batch and release its idmap_query_state_t object */
void idmap_lookup_release_batch(idmap_query_state_t **state);

/*
 * Add a name->SID lookup
 *
 *  - 'dname' is optional; if NULL or empty string then 'name' has to be
 *  a user/group name qualified wih a domainname (e.g., foo@domain),
 *  else the 'name' must not be qualified and the domainname must be
 *  passed in 'dname'.
 *
 *  - if 'rid' is NULL then the output SID string will include the last
 *  RID, else it won't and the last RID value will be stored in *rid.
 *
 *  The caller must free() *sid.
 */
idmap_retcode idmap_name2sid_batch_add1(idmap_query_state_t *state,
		const char *name, const char *dname, int eunixtype,
		char **canonname, char **sid, rid_t *rid, int *sid_type,
		char **unixname, idmap_retcode *rc);
/*
 * Add a SID->name lookup
 *
 *  - 'rid' is optional; if NULL then 'sid' is expected to have the
 *  user/group RID present, else 'sid' is expected not to have it, and
 *  *rid will be used to qualify the given 'sid'
 *
 *  - 'dname' is optional; if NULL then the fully qualified user/group
 *  name will be stored in *name, else the domain name will be stored in
 *  *dname and the user/group name will be stored in *name without a
 *  domain qualifier.
 *
 *  The caller must free() *name and *dname (if present).
 */
idmap_retcode idmap_sid2name_batch_add1(idmap_query_state_t *state,
		const char *sid, const rid_t *rid, int eunixtype,
		char **name, char **dname, int *sid_type,
		char **unixname, idmap_retcode *rc);

/*
 * Add a unixname->SID lookup
 */
idmap_retcode idmap_unixname2sid_batch_add1(idmap_query_state_t *state,
		const char *unixname, int is_user, int is_wuser,
		char **sid, rid_t *rid, char **name, char **dname,
		int *sid_type, idmap_retcode *rc);

/*
 * Set unixname attribute names for the batch for AD-based name mapping
 */
void idmap_lookup_batch_set_unixattr(idmap_query_state_t *state,
		const char *unixuser_attr, const char *unixgroup_attr);

#ifdef __cplusplus
}
#endif

#endif	/* _ADUTILS_H */
