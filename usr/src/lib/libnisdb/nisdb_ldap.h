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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_NISDB_LDAP_H
#define	_NISDB_LDAP_H

#include <sys/time.h>
#include <thread.h>
#include <synch.h>
#include <pthread.h>
#include <rpcsvc/nis.h>

#include "ldap_parse.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Types supporting rpc.nisd configuration attributes */

/* nisplusLDAPinitialUpdate */
typedef enum {
	ini_none,
	from_ldap,
	from_ldap_update_only,
	to_ldap,
	to_ldap_update_only
} __nis_initial_update_t;

/* nisplusLDAPretrieveError */
typedef enum {
	use_cached,
	ret_retry,
	try_again,
	ret_unavail,
	no_such_name,
	fail
} __nis_retrieve_error_t;

/* nisplusLDAPstoreError */
typedef enum {
	sto_retry,
	system_error,
	sto_unavail,
	sto_fail
} __nis_store_error_t;

/* nisplusLDAPstoreErrorDisp */
typedef enum {
	std_delete_entry,
	abandon
} __nis_store_error_disp_t;

/* nisplusLDAPrefreshError */
typedef enum {
	continue_using,
	ref_retry,
	continue_using_retry,
	cache_expired,
	tryagain
} __nis_refresh_error_t;

/* nisplusLDAPthreadCreationError */
typedef enum {
	pass_error,
	cre_retry
} __nis_thread_creation_error_t;

/* nisplusLDAPdumpError */
typedef enum {
	de_retry,
	rollback,
	rollback_retry
} __nis_dump_error_t;

/* nisplusLDAPresyncService */
typedef enum {
	from_copy,
	directory_locked,
	from_live
} __nis_resync_service_t;

/* nisplusLDAPupdateBatching */
typedef enum {
	accumulate,
	bounded_accumulate,
	upd_none
} __nis_update_batching_t;

/* nisplusLDAPexclusiveWaitMode */
typedef enum {
	block,
	ewm_tryagain
} __nis_exclusive_wait_mode_t;

/* nisplusLDAPmatchFetch */
typedef enum {
	no_match_only,
	mat_always,
	mat_never
} __nis_match_fetch_t;

/* Keep track of desired number of attempts and timeout */
typedef struct {
	int		attempts;
	time_t		timeout;
} __nisdb_retry_t;

/* Table mapping (and related) information */
typedef struct {
	time_t			initTtlLo;	/* Initial lo TTL for table */
	time_t			initTtlHi;	/* Initial hi TTL for table */
	time_t			ttl;		/* TTL for table entries */
	time_t			*expire;	/* Expire times for entries */
	time_t			enumExpire;	/* Enumeration expiration */
	bool_t			fromLDAP;	/* Get data from LDAP ? */
	bool_t			toLDAP;		/* Write data to LDAP ? */
	bool_t			isMaster;	/* Are we master for this ? */
	__nis_retrieve_error_t	retrieveError;
	__nisdb_retry_t		retrieveErrorRetry;
	__nis_store_error_t	storeError;
	__nisdb_retry_t		storeErrorRetry;
	__nis_store_error_disp_t
				storeErrorDisp;
	__nis_refresh_error_t	refreshError;
	__nisdb_retry_t		refreshErrorRetry;
	__nis_match_fetch_t	matchFetch;
	__nis_table_mapping_t	*tm;
	zotypes			objType;
	zotypes			expireType;
	char			*objName;
	bool_t			isDeferredTable;
	mutex_t			enumLock;
	pthread_t		enumTid;
	int			enumStat;
	int			enumDeferred;
	uint_t			enumEntries;
	ulong_t			enumTime;	/* Microseconds */
} __nisdb_table_mapping_t;

/*
 * Configuration data used by the rpc.nisd proper, but not in libnisdb.
 */
typedef struct {
	__nis_initial_update_t		initialUpdate;
	__nis_thread_creation_error_t	threadCreationError;
	__nisdb_retry_t			threadCreationErrorTimeout;
	__nis_dump_error_t		dumpError;
	__nisdb_retry_t			dumpErrorTimeout;
	__nis_resync_service_t		resyncService;
	__nis_update_batching_t		updateBatching;
	__nisdb_retry_t			updateBatchingTimeout;
	__nis_exclusive_wait_mode_t	exclusiveWaitMode;
	int				numberOfServiceThreads;
	int				emulate_yp;
	int				maxRPCRecordSize;
} __nis_config_t;

extern __nisdb_table_mapping_t	ldapDBTableMapping;
extern __nis_config_t		ldapConfig;

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _NISDB_LDAP_H */
