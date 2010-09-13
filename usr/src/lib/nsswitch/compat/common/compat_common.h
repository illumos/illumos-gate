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
 * Common code and structures used by name-service-switch "compat" backends.
 */

#ifndef _COMPAT_COMMON_H
#define	_COMPAT_COMMON_H

#include <nss_common.h>
#include <nss_dbdefs.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct compat_backend *compat_backend_ptr_t;
typedef nss_status_t	(*compat_backend_op_t)(compat_backend_ptr_t, void *);

/*
 * ===> Fix da comments (and in files_common.h too...)
 * Iterator function for _nss_files_do_all(), which probably calls yp_all().
 *   NSS_NOTFOUND means "keep enumerating", NSS_SUCCESS means"return now",
 *   other values don't make much sense.  In other words we're abusing
 *   (overloading) the meaning of nss_status_t, but hey...
 * _nss_compat_XY_all() is a wrapper around _nss_files_do_all() that does the
 *   generic work for nss_XbyY_args_t backends (calls cstr2ent etc).
 */
typedef nss_status_t	(*files_do_all_func_t)(const char *, int, void *args);
/* ===> ^^ nuke this line */
typedef int		(*compat_XY_check_func)(nss_XbyY_args_t *);
typedef const char 	*(*compat_get_name)(nss_XbyY_args_t *);
typedef int		(*compat_merge_func)(compat_backend_ptr_t,
					    nss_XbyY_args_t	*,
					    const char		**fields);

typedef struct setofstrings	*strset_t;

struct compat_backend {
	compat_backend_op_t	*ops;
	int			n_ops;
	const char		*filename;
	FILE			*f;
	int			minbuf;
	char			*buf;
	int			linelen;	/* <== Explain use, lifetime */

	nss_db_initf_t		db_initf;
	nss_db_root_t		*db_rootp;	/* Shared between instances */
	nss_getent_t		db_context;	/* Per-instance enumeration */

	compat_get_name		getnamef;
	compat_merge_func	mergef;

	/* We wouldn't need all this hokey state stuff if we */
	/*   used another thread to implement a coroutine... */
	enum {
		GETENT_FILE,
		GETENT_NETGROUP,
		GETENT_ATTRDB,
		GETENT_ALL,
		GETENT_DONE
	}			state;
	strset_t		minuses;

	int			permit_netgroups;
	const char		*yp_domain;
	nss_backend_t		*getnetgrent_backend;
	char			*netgr_buffer;
	int			return_string_data;
	int			(*str2ent_save)();
	int			(*str2ent_alt)();
	void			*workarea;
};

#if defined(__STDC__)
extern nss_backend_t	*_nss_compat_constr(compat_backend_op_t	*ops,
					    int			n_ops,
					    const char		*filename,
					    int			min_bufsize,
					    nss_db_root_t	*rootp,
					    nss_db_initf_t	initf,
					    int			netgroups,
					    compat_get_name	getname_func,
					    compat_merge_func	merge_func);
extern nss_status_t	_nss_compat_destr(compat_backend_ptr_t, void *dummy);
extern nss_status_t	_nss_compat_setent(compat_backend_ptr_t, void *dummy);
extern nss_status_t	_nss_compat_endent(compat_backend_ptr_t, void *dummy);
extern nss_status_t	_nss_compat_getent(compat_backend_ptr_t, void *);
extern nss_status_t 	_nss_compat_XY_all(compat_backend_ptr_t,
					nss_XbyY_args_t	*args,
					compat_XY_check_func	check,
					nss_dbop_t		op_num);
extern nss_status_t 	_attrdb_compat_XY_all(compat_backend_ptr_t,
					nss_XbyY_args_t	*args,
					int netdb,
					compat_XY_check_func	check,
					nss_dbop_t		op_num);
#else
extern nss_backend_t	*_nss_compat_constr();
extern nss_status_t	_nss_compat_destr();
extern nss_status_t	_nss_compat_setent();
extern nss_status_t	_nss_compat_endent();
extern nss_status_t	_nss_compat_getent();
extern nss_status_t	_nss_compat_XY_all();
extern nss_status_t	_attrdb_compat_XY_all();
#endif

/* functions to validate passwd and group ids */
extern int validate_passwd_ids(char *line, int *linelenp, int buflen,
	int extra_chars);
extern int validate_group_ids(char *line, int *linelenp, int buflen,
	int extra_chars);

#ifdef	__cplusplus
}
#endif

#endif /* _COMPAT_COMMON_H */
