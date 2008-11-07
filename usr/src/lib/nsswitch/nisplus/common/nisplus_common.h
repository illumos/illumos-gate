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

/*
 *	Common code used by name-service-switch "nisplus" backends
 */

#ifndef _NISPLUS_COMMON_H
#define	_NISPLUS_COMMON_H

#include <nss_dbdefs.h>
#include <rpcsvc/nis.h>

/*
 * We want these flags turned on in all nis_list() requests that we perform;
 * other flags (USE_DGRAM, EXPAND_NAME) are only wanted for some requests.
 */
#define	NIS_LIST_COMMON	(FOLLOW_LINKS | FOLLOW_PATH)

/* See the comment in $SRC/lib/nsswitch/ldap/common/ldap_common.h */
#define	NOBODY_STR_LEN	21

typedef struct nisplus_backend	*nisplus_backend_ptr_t;

typedef nss_status_t (*nisplus_backend_op_t)(nisplus_backend_ptr_t, void *);
typedef int (*nisplus_obj2str_func)(int nobjs, nis_object *obj,
				nisplus_backend_ptr_t be,
				nss_XbyY_args_t	*arg);
struct nisplus_backend {
	nisplus_backend_op_t	*ops;
	nss_dbop_t		n_ops;
	const char		*directory; /* fully qualified directory */

	/*
	 * table_name is fully qualified (includes org_dir and
	 * directory name) and cached here using one time malloc.
	 */
	char			*table_name;

	nisplus_obj2str_func	obj2str;
	struct {
		struct netobj	no;
		uint_t		max_len;
	} cursor;

	/*
	 * Fields for handling table paths during enumeration.
	 * The path_list field is allocated dynamically because
	 * it is kind of big and most applications don't do
	 * enumeration.
	 */
	char			*table_path;
	int			path_index;
	int			path_count;
	nis_name		*path_list;

	/*
	 * Internal fields to support NSS2 format
	 */
	char			*buffer;
	int			buflen;
	uint8_t			flag;
};
typedef struct nisplus_backend nisplus_backend_t;

#if defined(__STDC__)
extern nss_backend_t	*_nss_nisplus_constr(nisplus_backend_op_t *ops,
						int n_ops,
						const char *rdn,
						nisplus_obj2str_func func);
extern nss_status_t	_nss_nisplus_destr(nisplus_backend_ptr_t,
						void *dummy);
extern nss_status_t	_nss_nisplus_setent(nisplus_backend_ptr_t,
						void *dummy);
extern nss_status_t  	_nss_nisplus_endent(nisplus_backend_ptr_t,
						void *dummy);
extern nss_status_t  	_nss_nisplus_getent(nisplus_backend_ptr_t,
						void *arg);
extern nss_status_t	_nss_nisplus_lookup(nisplus_backend_ptr_t,
						nss_XbyY_args_t	*arg,
						const char *key,
						const char *val);
extern nss_status_t	_nss_nisplus_expand_lookup(nisplus_backend_ptr_t,
						nss_XbyY_args_t	*arg,
						const char *key,
						const char *val,
						const char *table);
extern int		nis_aliases_object2str(nis_object *obj,
						int nobj,
						const char *cname,
						const char *proto,
						char *linep,
						char *limit);
extern int		nis_hosts_object2str(int nobj,
						nis_object *obj,
						nisplus_backend_ptr_t be,
						nss_XbyY_args_t *argp,
						int af);
#else	/* __STDC__ */
extern nss_backend_t	*_nss_nisplus_constr();
extern nss_status_t	_nss_nisplus_destr();
extern nss_status_t	_nss_nisplus_setent();
extern nss_status_t  	_nss_nisplus_endent();
extern nss_status_t  	_nss_nisplus_getent();
extern nss_status_t	_nss_nisplus_lookup();
extern nss_status_t	_nss_nisplus__expand_lookup();
extern int build_aliases_from_nisobj();
#endif	/* __STDC__ */

/* Lower-level interface */
extern nss_status_t	_nss_nisplus_list(const char *name,
						int extra_flags,
						nis_result **r);
extern int __nis_parse_path();
extern int thr_main(void);
extern int __nss2herrno();
extern char *inet_ntoa_r();

#endif	/* _NISPLUS_COMMON_H */
