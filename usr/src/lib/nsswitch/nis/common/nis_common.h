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
 * nis_common.h
 *
 * Common code and structures used by name-service-switch "nis" backends.
 */

#ifndef _NIS_COMMON_H
#define	_NIS_COMMON_H

#include <nss_dbdefs.h>
#include <stdlib.h>
#include <strings.h>
#include <signal.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NIS_MAP_AUDITUSER	"audit_user"
#define	NIS_MAP_AUTHATTR	"auth_attr"
#define	NIS_MAP_EXECATTR	"exec_attr"
#define	NIS_MAP_PROFATTR	"prof_attr"
#define	NIS_MAP_USERATTR	"user_attr"


typedef struct nis_backend *nis_backend_ptr_t;
typedef nss_status_t	(*nis_backend_op_t)(nis_backend_ptr_t, void *);

struct nis_backend {
	nis_backend_op_t	*ops;
	nss_dbop_t		n_ops;
	const char		*domain;
	const char		*enum_map;
	char			*enum_key;
	int			enum_keylen;
};

/*
 * Iterator function for _nss_nis_do_all(), which probably calls yp_all().
 *   NSS_NOTFOUND means "keep enumerating", NSS_SUCCESS means"return now",
 *   other values don't make much sense.  In other words we're abusing
 *   (overloading) the meaning of nss_status_t, but hey...
 * _nss_nis_XY_all() is a wrapper around _nss_nis_do_all() that does the
 *   generic work for nss_XbyY_args_t backends (calls cstr2ent etc).
 */
typedef nss_status_t	(*nis_do_all_func_t)(const char *, int, void *priv);
typedef int		(*nis_XY_check_func)(nss_XbyY_args_t *);

extern nss_backend_t	*_nss_nis_constr(nis_backend_op_t	*ops,
					int			n_ops,
					const char		*map);
extern nss_status_t	_nss_nis_destr(nis_backend_ptr_t, void *dummy);
extern nss_status_t	_nss_nis_setent(nis_backend_ptr_t, void *dummy);
extern nss_status_t  	_nss_nis_endent(nis_backend_ptr_t, void *dummy);
extern nss_status_t  	_nss_nis_getent_rigid(nis_backend_ptr_t, void *);
extern nss_status_t  	_nss_nis_getent_netdb(nis_backend_ptr_t, void *);
extern nss_status_t 	_nss_nis_do_all(nis_backend_ptr_t,
					void			*func_priv,
					const char		*filter,
					nis_do_all_func_t	func);
extern nss_status_t 	_nss_nis_XY_all(nis_backend_ptr_t,
					nss_XbyY_args_t		*check_args,
					int			netdb,
					const char		*filter,
					nis_XY_check_func	check);
extern nss_status_t	_nss_nis_lookup(nis_backend_ptr_t,
					nss_XbyY_args_t		*args,
					int			netdb,
					const char		*map,
					const char		*key,
					int			*yp_statusp);
extern nss_status_t _nss_nis_lookup_rsvdport(nis_backend_ptr_t   be,
					nss_XbyY_args_t	*args,
					int netdb,
					const char	*map,
					const char	*key,
					int	*ypstatusp);

/* Lower-level interface */
extern nss_status_t	_nss_nis_ypmatch(const char		*domain,
					const char		*map,
					const char		*key,
					char			**valp,
					int			*vallenp,
					int			*yp_statusp);
extern const char	*_nss_nis_domain();
extern int __nss2herrno(nss_status_t nsstat);
extern int thr_sigsetmask(int how, const sigset_t *set, sigset_t *oset);
extern int _nss_nis_check_name_aliases(nss_XbyY_args_t *argp,
					const char *line,
					int linelen);

/* private yp "configurable lookup persistence" interface in libnsl */
extern int __yp_match_cflookup(char *, char *, char *, int, char **,
			    int *, int *);
extern int __yp_match_rsvdport_cflookup(char *, char *, char *, int, char **,
				    int *, int *);
extern int __yp_first_cflookup(char *, char *, char **, int *, char **,
			    int *, int);

extern int __yp_next_cflookup(char *, char *, char *, int, char **, int *,
			    char **, int  *, int);

extern int __yp_all_cflookup(char *, char *, struct ypall_callback *, int);

/* functions to validate passwd and group ids */
extern int validate_passwd_ids(char **linepp, int *linelenp, int allocbuf);
extern int validate_group_ids(char **linepp, int *linelenp, int allocbuf);

#ifdef	__cplusplus
}
#endif

#endif /* _NIS_COMMON_H */
