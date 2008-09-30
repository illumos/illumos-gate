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

#ifndef	_NSCD_SWITCH_H
#define	_NSCD_SWITCH_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nss_dbdefs.h>
#include <thread.h>
#include <libscf.h>
#define	__NSS_PRIVATE_INTERFACE
#include "nsswitch_priv.h"
#undef	__NSS_PRIVATE_INTERFACE
#include "nscd_db.h"
#include "nscd_config.h"

/*
 * max. length of e.g. "passwd: files ldap"
 */
#define	MAX_NSSWITCH_CONFIG_STRING_SZ 256

/*
 * max. length of the name of a NSS database
 */
#define	MAX_NSSWITCH_CONFIG_DB_NAME_SZ 256

/*
 * nscd_nsw_config_t is an abstraction of the configuration
 * for a NSS database
 */
typedef struct {
	char				*db_name;
	char				*nsw_cfg_str;
	nss_db_params_t			fe_params;
	struct __nsw_switchconfig_v1	*nsw_config;
	int				max_src;
	int				*src_idx;	/* ptr to array of */
							/* src index */
	int				nobase;		/* not shared */
} nscd_nsw_config_t;

/*
 * nscd_be_info_t is an abstraction of a NSS backend
 */
typedef struct {
	void			*be_version;
	nss_backend_constr_t	be_constr;
	nss_backend_finder_t	*finder;
	void			*finder_priv;
} nscd_be_info_t;

/*
 * nscd_state_ctrl_t is used to control a nscd_nsw_state pool
 */
typedef struct {
	int			max;
	int			allocated;
	int			free;
	int			waiter;
	struct nscd_nsw_state	*first;
} nscd_state_ctrl_t;

/*
 * nscd_nsw_state_base_t represents the nscd_nsw_state pool
 * for a NSS database
 */
typedef struct nscd_nsw_state_base {
	int			dbi;	/* which database? */
	nscd_state_ctrl_t	nsw_state;
	nscd_state_ctrl_t	nsw_state_thr;
	int			used_by_thr;
	thread_t		tid;
	cond_t			thr_cond;
} nscd_nsw_state_base_t;

/*
 * nscd_nsw_state_t is an abstraction of all the data needed
 * to do lookup of NSS database (e.g. "passwd" or "hosts")
 */
extern	void *_nscd_be_version;		/* default version for supported be */
typedef struct nscd_nsw_state {
	int				dbi;	/* which database? */
	int				max_src; /* is == config->num_lookups */
	int				getent; /* used by getent */
	nscd_bool_t			recheck_be; /* if set, check/init be */
	nss_db_params_t			p;
	struct __nsw_switchconfig_v1	*config;
	nscd_nsw_config_t		**nsw_cfg_p;
	nscd_nsw_state_base_t		*base;
	nss_backend_t			**be; /* array of backends */
	nss_backend_constr_t		*be_constr; /* be constructor array */
	nscd_db_t			***be_db_pp;
	void				**be_version_p; /* version ptr array */
	struct nscd_nsw_state		*next;
} nscd_nsw_state_t;

/*
 * nscd_getent_ctx_base_t represents the nscd_getent_ctx_base_t pool
 * for a NSS database
 */
typedef struct nscd_getent_ctx_base {
	int			dbi;		/* which database? */
	int			deattached;	/* not associated with */
						/* current config */
	int			max_getent_ctx;
	int			num_getent_ctx;
	int			num_waiter;
	struct nscd_getent_context *first;
} nscd_getent_ctx_base_t;

/*
 * nscd_getent_context_t is an abstraction of all the data needed
 * to enumerate a NSS database (e.g. "passwd" or "hosts")
 */
typedef struct nscd_getent_context {
	int				dbi;
	thread_t			thr_id;
	mutex_t				getent_mutex;
	int				aborted;
	int				in_use;
	int				num_reclaim_check;
	nscd_seq_num_t			seq_num;
	nscd_cookie_num_t		cookie_num;
	pid_t				pid;	/* door client's pid */
	int				n_src;	/* >=max_src: end of sequence */
	nscd_nsw_state_t		*nsw_state;
	nss_backend_t			*be;
	nscd_getent_ctx_base_t		*base;
	struct nscd_getent_context	*next;
	struct nscd_getent_context	*next_to_reclaim;
} nscd_getent_context_t;

/*
 * nscd_smf_state_t is used to keep track of the state of the smf
 * service associated with a NSS source (e.g. "passwd" or "hosts")
 */
typedef struct {
	char	*src_name;
	int	src_state;
} nscd_smf_state_t;

/*
 * nscd_smf_state_t is used to keep track of the state of the smf
 * service associated with a NSS source (e.g. "passwd" or "hosts")
 */
typedef struct {
	int			dbi;		/* database index */
	/*
	 * index of the database of which the switch policy
	 * should be used
	 */
	int			cfgdbi;
	/*
	 * index of the pseudo database that the NSS backend
	 * does search on
	 */
	int			compati;
	/*
	 * ptr to ptr to the siwtch config structure
	 */
	nscd_nsw_config_t	**nswcfg;
	/*
	 * frontend params passed to nss_search or nss_*ent
	 */
	struct nss_db_params	p;
	/*
	 * set to 1 if database is "hosts", else 2 if "ipnodes"
	 */
	int8_t			dnsi;
	/*
	 * set to 1 if require privilege to look up the database
	 */
	uint8_t			privdb;
} nscd_nsw_params_t;

/*
 * additional info returned by the switch engine
 */
typedef struct {
	void	*pbuf;	/* ptr to packed buffer */
	size_t	pbufsiz; /* length of the packed buffer */
	int	srci;	/* last source searched */
	int	errnum; /* errno from the backend */
	int	noarg; /* if set, backend does not use the arg structure */
	int	fallback; /* if set, may need to fall back to main nscd */
	int	datalen; /* pbuf->data_len (backend may change it) */
} nscd_sw_return_t;

/*
 * nscd cookies used for setent/getent/endent
 * - p0 cookie: returned by nscd to indicate
 *              the start of the enumeration position
 * - p1 cookie: returned/updated by nscd to indicate
 *              the current enumeration position
 */
#define	NSCD_P0_COOKIE_SEQNUM	-1
typedef struct {
	pid_t		p0_pid;
	time_t		p0_time;
	nscd_seq_num_t	p0_seqnum;
} nscd_getent_p0_cookie_t;

typedef struct {
	nscd_cookie_num_t	p1_cookie_num;
	nscd_seq_num_t		p1_seqnum;
} nscd_getent_p1_cookie_t;

/*
 * static tables or global data defined in other files
 */
extern int			_nscd_cfg_num_nsw_src;
extern int			_nscd_cfg_num_nsw_src_all;
extern int			_nscd_cfg_num_nsw_db;
extern int			_nscd_cfg_num_nsw_db_all;
extern int			_nscd_cfg_num_smf_services;
extern nscd_cfg_id_t		_nscd_cfg_nsw_src[];
extern nscd_cfg_id_t		*_nscd_cfg_nsw_src_all;
extern nscd_cfg_id_t		_nscd_cfg_nsw_db[];
extern nss_db_initf_t		nscd_nss_db_initf[];
extern nscd_cfg_id_t		_nscd_cfg_smf_services[];
extern nscd_smf_state_t		*nscd_smf_service_state;
extern nscd_db_t		***nscd_src_backend_db;
extern nscd_nsw_config_t	***nscd_nsw_config;
extern nscd_nsw_state_base_t	**nscd_nsw_state_base;
extern nscd_getent_ctx_base_t	**nscd_getent_ctx_base;
extern nscd_cfg_global_switch_t	nscd_switch_cfg_g;
extern nscd_cfg_switch_t	*nscd_switch_cfg;
extern nscd_cfg_stat_global_switch_t nscd_switch_stats_g;
extern nscd_cfg_stat_switch_t	*nscd_switch_stats;

#define	NSCD_NUM_SRC		_nscd_cfg_num_nsw_src_all
#define	NSCD_NUM_DB		_nscd_cfg_num_nsw_db_all
#define	NSCD_NUM_SMF_FMRI	_nscd_cfg_num_smf_services
#define	NSCD_NSW_SRC_NAME(i)	(_nscd_cfg_nsw_src_all + i)->name
#define	NSCD_NSW_DB_NAME(i)	_nscd_cfg_nsw_db[i].name
#define	NSCD_SMF_SVC_FMRI(i)	_nscd_cfg_smf_services[i].name
#define	NSCD_SMF_SVC_INDEX(i)	_nscd_cfg_smf_services[i].index
#define	NSCD_SMF_SVC_STATE(i)	nscd_smf_service_state[i].src_state
#define	NSCD_SW_CFG_G		nscd_switch_cfg_g
#define	NSCD_SW_CFG(i)		nscd_switch_cfg[i]
#define	NSCD_SW_STATS_G		nscd_switch_stats_g
#define	NSCD_SW_STATS(i)	nscd_switch_stats[i]

/*
 * special service states used by the switch engine
 */
#define	NSCD_SVC_STATE_UNINITED		-1
#define	NSCD_SVC_STATE_FOREIGN_SRC	-2
#define	NSCD_SVC_STATE_UNSUPPORTED_SRC	-3

/*
 * prototypes
 */

void
_nscd_put_nsw_state(
	nscd_nsw_state_t	*s);

void
_nscd_put_nsw_state_thread(
	nscd_nsw_state_t	*s);

nscd_rc_t
_nscd_get_nsw_state(
	nss_db_root_t		*rootp,
	nscd_nsw_params_t	*params);

nscd_rc_t
_nscd_get_nsw_state_thread(
	nss_db_root_t		*rootp,
	nscd_nsw_params_t	*params);

nscd_rc_t
_nscd_init_all_nsw_state_base();

nscd_rc_t
_nscd_init_nsw_state_base(
	int			dbi,
	int			compat_basei,
	int			lock);

nscd_rc_t
_nscd_init_all_getent_ctx();

nscd_rc_t
_nscd_init_getent_ctx_base(
	int			dbi,
	int			lock);

nscd_db_t
*_nscd_create_getent_ctxaddrDB();

nscd_rc_t
_nscd_get_getent_ctx(
	nss_getent_t		*contextpp,
	nscd_nsw_params_t	*params);

void
_nscd_put_getent_ctx(
	nscd_getent_context_t	*ctx);
void
_nscd_free_ctx_if_aborted(
	nscd_getent_context_t	*ctx);

int
_nscd_is_getent_ctx_in_use(
	nscd_getent_context_t	*ctx);

nscd_rc_t
_nscd_init_all_nsw_config();

nscd_rc_t
_nscd_init_all_nsw_be_info_db();

#ifdef NSCD_NSSWITCH_CONF_FROM_SMF_PROP
nscd_rc_t
_nscd_get_new_nsw_config(
	scf_handle_t		*hndl,
	const char		*fmri,
	scf_propertygroup_t	*pg);
#endif

nscd_rc_t
_nscd_get_new_service_state(
	int			index,
	scf_handle_t		*hndl,
	scf_property_t		*prop);

nscd_getent_context_t *
_nscd_is_getent_ctx(
	nscd_cookie_num_t	cookie_num);

nscd_rc_t
_nscd_create_sw_struct(
	int			dbi,
	int			compat_basei,
	const char		*dbn,
	const char		*cfgstr,
	void			*swcfgv1,
	nscd_nsw_params_t	*params);

nscd_rc_t
_nscd_create_new_config(
	nscd_nsw_params_t	*params);

void
_nscd_free_nsw_config(
	nscd_nsw_config_t	*nswcfg);

nscd_rc_t
_nscd_init_smf_monitor();

nscd_rc_t
_nscd_alloc_nsw_config();

nscd_rc_t
_nscd_alloc_service_state_table();

nscd_rc_t
_nscd_alloc_nsw_state_base();

nscd_rc_t
_nscd_alloc_nsw_be_info_db();

nscd_rc_t
_nscd_alloc_getent_ctx_base();

void
_nscd_free_all_nsw_state_base();

void
_nscd_free_all_getent_ctx_base();

void
_nscd_free_all_nsw_config();

void
_nscd_free_all_nsw_backend_info_db();

struct __nsw_switchconfig_v1 *
_nsw_getoneconfig_v1(
	const char		*name,
	char			*linep,
	enum __nsw_parse_err	*errp);
int
__nsw_freeconfig_v1(
	struct __nsw_switchconfig_v1 *conf);

int
_nscd_get_smf_state(int srci, int dbi, int recheck);

void
nss_psearch(void *buffer, size_t length);
void
nss_psetent(void *buffer, size_t length, pid_t pid);
void
nss_pgetent(void *buffer, size_t length);
void
nss_pendent(void *buffer, size_t length);
void
nss_pdelete(void *buffer, size_t length);

nscd_rc_t _nscd_alloc_switch_cfg();
nscd_rc_t _nscd_alloc_switch_stats();
nscd_db_t *_nscd_create_getent_ctx_addrDB();
nscd_db_t *_nscd_create_getent_ctxDB();

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_SWITCH_H */
