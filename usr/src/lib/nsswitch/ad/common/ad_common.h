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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_AD_COMMON_H
#define	_AD_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <nss_dbdefs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <idmap.h>
#include <sys/idmap.h>
#include <rpcsvc/idmap_prot.h>
#include <idmap_priv.h>
#include "addisc.h"
#include "libadutils.h"

#define	_GROUP	"group"
#define	_PASSWD	"passwd"
#define	_SHADOW	"shadow"

#define	WK_DOMAIN	"BUILTIN"
#define	CFG_QUEUE_MAX_SIZE	15

#define	SEARCHFILTERLEN		256
#define	RESET_ERRNO()\
	if (errno == EINVAL)\
		errno = 0;

/*
 * Superset the nss_backend_t abstract data type. This ADT has
 * been extended to include AD associated data structures.
 */

typedef struct ad_backend *ad_backend_ptr;
typedef nss_status_t (*ad_backend_op_t)(ad_backend_ptr, void *);
typedef int (*fnf)(ad_backend_ptr be, nss_XbyY_args_t *argp);

typedef enum {
	NSS_AD_DB_NONE		= 0,
	NSS_AD_DB_PASSWD_BYNAME	= 1,
	NSS_AD_DB_PASSWD_BYUID	= 2,
	NSS_AD_DB_GROUP_BYNAME	= 3,
	NSS_AD_DB_GROUP_BYGID	= 4,
	NSS_AD_DB_SHADOW_BYNAME	= 5
} nss_ad_db_type_t;

struct ad_backend {
	ad_backend_op_t		*ops;
	nss_dbop_t		nops;
	char			*tablename;
	const char		**attrs;
	fnf			adobj2str;
	char			*buffer;
	int			buflen;
	uid_t			uid;
	adutils_result_t	*result;
	nss_ad_db_type_t	db_type;
};

typedef struct nssad_prop {
	char			*domain_name;
	ad_disc_ds_t	*domain_controller;
} nssad_prop_t;

typedef struct nssad_cfg {
	pthread_rwlock_t	lock;
	nssad_prop_t		props;
	ad_disc_t		ad_ctx;
	adutils_ad_t		*ad;
	struct nssad_cfg	*qnext;
} nssad_cfg_t;

typedef struct nssad_state {
	nssad_cfg_t		*qhead;
	nssad_cfg_t		*qtail;
	uint32_t		qcount;
} nssad_state_t;

extern nss_status_t	_nss_ad_destr(ad_backend_ptr be, void *a);
extern nss_status_t	_nss_ad_endent(ad_backend_ptr be, void *a);
extern nss_status_t	_nss_ad_setent(ad_backend_ptr be, void *a);
extern nss_status_t	_nss_ad_getent(ad_backend_ptr be, void *a);
nss_backend_t		*_nss_ad_constr(ad_backend_op_t ops[], int nops,
			char *tablename, const char **attrs, fnf ldapobj2str);
extern nss_status_t	_nss_ad_lookup(ad_backend_ptr be,
			nss_XbyY_args_t *argp, const char *database,
			const char *searchfilter, const char *dname,
			int *try_idmap);
extern nss_status_t	_nss_ad_marshall_data(ad_backend_ptr be,
			nss_XbyY_args_t *argp);
extern nss_status_t	_nss_ad_sanitize_status(ad_backend_ptr be,
			nss_XbyY_args_t *argp, nss_status_t stat);
extern int		_ldap_filter_name(char *filter_name, const char *name,
			int filter_name_size);


#ifdef	__cplusplus
}
#endif

#endif	/* _AD_COMMON_H */
