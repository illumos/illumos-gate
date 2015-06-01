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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _IDMAPD_H
#define	_IDMAPD_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <rpc/rpc.h>
#include <synch.h>
#include <thread.h>
#include <libintl.h>
#include <strings.h>
#include <sqlite-sys/sqlite.h>
#include <syslog.h>
#include <inttypes.h>
#include <rpcsvc/idmap_prot.h>
#include "adutils.h"
#include "idmap_priv.h"
#include "idmap_config.h"
#include "libadutils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	CHECK_NULL(s)	(s != NULL ? s : "null")

extern mutex_t _svcstate_lock;	/* lock for _rpcsvcstate, _rpcsvccount */

typedef enum idmap_namemap_mode {
	IDMAP_NM_NONE = 0,
	IDMAP_NM_AD,
	IDMAP_NM_NLDAP,
	IDMAP_NM_MIXED
} idmap_namemap_mode_t;

/*
 * Debugging output.
 *
 * There are some number of areas - configuration, mapping, discovery, et
 * cetera - and for each area there is a verbosity level controlled through
 * an SMF property.  The default is zero, and "debug/all" provides a master
 * control allowing you to turn on all debugging output with one setting.
 *
 * A typical debugging output sequence would look like
 *
 * 	if (DBG(CONFIG, 2)) {
 *		idmapdlog(LOG_DEBUG,
 *		    "some message about config at verbosity 2");
 *	}
 */
enum idmapd_debug {
	IDMAPD_DEBUG_ALL = 0,
	IDMAPD_DEBUG_CONFIG = 1,
	IDMAPD_DEBUG_MAPPING = 2,
	IDMAPD_DEBUG_DISC = 3,
	IDMAPD_DEBUG_DNS = 4,
	IDMAPD_DEBUG_LDAP = 5,
	IDMAPD_DEBUG_MAX = 5
};

#define	DBG(type, lev)	\
	(_idmapdstate.debug[IDMAPD_DEBUG_##type] >= (lev) || \
	    _idmapdstate.debug[IDMAPD_DEBUG_ALL] >= (lev))

/*
 * Global state of idmapd daemon.
 */
typedef struct idmapd_state {
	rwlock_t	rwlk_cfg;		/* config lock */
	idmap_cfg_t	*cfg;			/* config */
	bool_t		daemon_mode;
	char		hostname[MAX_NAME_LEN];	/* my hostname */
	uid_t		next_uid;
	gid_t		next_gid;
	uid_t		limit_uid;
	gid_t		limit_gid;
	int		new_eph_db;	/* was the ephem ID db [re-]created? */
	int		num_gcs;
	adutils_ad_t	**gcs;
	int		num_dcs;
	adutils_ad_t	**dcs;
	int		debug[IDMAPD_DEBUG_MAX+1];
} idmapd_state_t;
extern idmapd_state_t	_idmapdstate;

#define	RDLOCK_CONFIG() \
	(void) rw_rdlock(&_idmapdstate.rwlk_cfg);
#define	WRLOCK_CONFIG() \
	(void) rw_wrlock(&_idmapdstate.rwlk_cfg);
#define	UNLOCK_CONFIG() \
	(void) rw_unlock(&_idmapdstate.rwlk_cfg);

typedef struct hashentry {
	uint_t	key;
	uint_t	next;
} hashentry_t;

typedef struct lookup_state {
	bool_t			sid2pid_done;
	bool_t			pid2sid_done;
	int			ad_nqueries;
	int			nldap_nqueries;
	bool_t			eph_map_unres_sids;
	int			directory_based_mapping;	/* enum */
	uint_t			id_cache_timeout;
	uint_t			name_cache_timeout;
	uint_t			curpos;
	hashentry_t		*sid_history;
	uint_t			sid_history_size;
	idmap_mapping_batch	*batch;
	idmap_ids_res		*result;
	idmap_namemap_mode_t	nm_siduid;
	idmap_namemap_mode_t	nm_sidgid;
	char			*ad_unixuser_attr;
	char			*ad_unixgroup_attr;
	char			*nldap_winname_attr;
	char			*defdom;
	sqlite			*cache;
	sqlite			*db;
} lookup_state_t;

#define	NLDAP_OR_MIXED(nm) \
	((nm) == IDMAP_NM_NLDAP || (nm) == IDMAP_NM_MIXED)
#define	AD_OR_MIXED(nm) \
	((nm) == IDMAP_NM_AD || (nm) == IDMAP_NM_MIXED)

#define	PID_UID_OR_UNKNOWN(pidtype) \
	((pidtype) == IDMAP_UID || (pidtype) == IDMAP_POSIXID)
#define	PID_GID_OR_UNKNOWN(pidtype) \
	((pidtype) == IDMAP_GID || (pidtype) == IDMAP_POSIXID)

#define	NLDAP_OR_MIXED_MODE(pidtype, ls) \
	(NLDAP_MODE(pidtype, ls) || MIXED_MODE(pidtype, ls))
#define	AD_OR_MIXED_MODE(pidtype, ls)\
	(AD_MODE(pidtype, ls) || MIXED_MODE(pidtype, ls))
#define	NLDAP_MODE(pidtype, ls) \
	((PID_UID_OR_UNKNOWN(pidtype) && (ls)->nm_siduid == IDMAP_NM_NLDAP) || \
	(PID_GID_OR_UNKNOWN(pidtype) && (ls)->nm_sidgid == IDMAP_NM_NLDAP))
#define	AD_MODE(pidtype, ls) \
	((PID_UID_OR_UNKNOWN(pidtype) && (ls)->nm_siduid == IDMAP_NM_AD) || \
	(PID_GID_OR_UNKNOWN(pidtype) && (ls)->nm_sidgid == IDMAP_NM_AD))
#define	MIXED_MODE(pidtype, ls) \
	((PID_UID_OR_UNKNOWN(pidtype) && (ls)->nm_siduid == IDMAP_NM_MIXED) || \
	(PID_GID_OR_UNKNOWN(pidtype) && (ls)->nm_sidgid == IDMAP_NM_MIXED))


typedef struct list_cb_data {
	void		*result;
	uint64_t	next;
	uint64_t	len;
	uint64_t	limit;
	int		flag;
} list_cb_data_t;

typedef struct msg_table {
	idmap_retcode	retcode;
	const char	*msg;
} msg_table_t;

/*
 * Data structure to store well-known SIDs and
 * associated mappings (if any)
 */
typedef struct wksids_table {
	const char	*sidprefix;
	uint32_t	rid;
	const char	*domain;
	const char	*winname;
	int		is_wuser;
	posix_id_t	pid;
	int		is_user;
	int		direction;
} wksids_table_t;

#define	IDMAPD_SEARCH_TIMEOUT		3   /* seconds */
#define	IDMAPD_LDAP_OPEN_TIMEOUT	1   /* secs; initial, w/ exp backoff */

/*
 * The following flags are used by idmapd while processing a
 * given mapping request. Note that idmapd uses multiple passes to
 * process the request and the flags are used to pass information
 * about the state of the request between these passes.
 */

/* Initial state. Done. Reset all flags. Remaining passes can be skipped */
#define	_IDMAP_F_DONE			0x00000000
/* Set when subsequent passes are required */
#define	_IDMAP_F_NOTDONE		0x00000001
/* Don't update name_cache. (e.g. set when winname,SID found in name_cache) */
#define	_IDMAP_F_DONT_UPDATE_NAMECACHE	0x00000002
/* Batch this request for AD lookup */
#define	_IDMAP_F_LOOKUP_AD		0x00000004
/* Batch this request for nldap directory lookup */
#define	_IDMAP_F_LOOKUP_NLDAP		0x00000008
/*
 * Expired ephemeral mapping found in cache when processing sid2uid request.
 * Use it if the given SID cannot be mapped by name
 */
#define	_IDMAP_F_EXP_EPH_UID		0x00000010
/* Same as above. Used for sid2gid request */
#define	_IDMAP_F_EXP_EPH_GID		0x00000020
/* This request is not valid for the current forest */
#define	_IDMAP_F_LOOKUP_OTHER_AD	0x00000040


/*
 * Check if we are done. If so, subsequent passes can be skipped
 * when processing a given mapping request.
 */
#define	ARE_WE_DONE(f)	((f & _IDMAP_F_NOTDONE) == 0)

#define	SIZE_INCR	5
#define	MAX_TRIES	5
#define	IDMAP_DBDIR	"/var/idmap"
#define	IDMAP_CACHEDIR	"/var/run/idmap"
#define	IDMAP_DBNAME	IDMAP_DBDIR "/idmap.db"
#define	IDMAP_CACHENAME	IDMAP_CACHEDIR "/idmap.db"

#define	IS_ID_NONE(id)	\
	((id).idtype == IDMAP_NONE)

#define	IS_ID_SID(id)	\
	((id).idtype == IDMAP_SID ||	\
	(id).idtype == IDMAP_USID ||	\
	(id).idtype == IDMAP_GSID)	\

#define	IS_ID_UID(id)	\
	((id).idtype == IDMAP_UID)

#define	IS_ID_GID(id)	\
	((id).idtype == IDMAP_GID)

#define	IS_ID_POSIX(id)	\
	((id).idtype == IDMAP_UID ||	\
	(id).idtype == IDMAP_GID ||	\
	(id).idtype == IDMAP_POSIXID)	\

/*
 * Local RID ranges
 */
#define	LOCALRID_UID_MIN	1000U
#define	LOCALRID_UID_MAX	((uint32_t)INT32_MAX)
#define	LOCALRID_GID_MIN	(((uint32_t)INT32_MAX) + 1)
#define	LOCALRID_GID_MAX	UINT32_MAX

/*
 * Tracing.
 *
 * The tracing mechanism is intended to help the administrator understand
 * why their mapping configuration is doing what it is.  Each interesting
 * decision point during the mapping process calls TRACE() with the current
 * request and response and a printf-style message.  The message, plus
 * data from the request and the response, is logged to the service log
 * (if debug/mapping is greater than zero) or reported to the caller
 * (if IDMAP_REQ_FLG_TRACE was set in the request.  The primary consumer
 * is the "-V" option to "idmap show".
 *
 * TRACING(req) says whether tracing is appropriate for the request, and
 * is used to determine and record whether any request in a batch requested
 * tracing, to control whether later code loops over the batch to do tracing
 * for any of the requests.
 *
 * TRACE(req, res, fmt, ...) generates a trace entry if appropriate.
 */
#define	TRACING(req)	\
	(DBG(MAPPING, 1) ||	\
	((req)->flag & IDMAP_REQ_FLG_TRACE) != 0)
#define	TRACE(req, res, ...)			\
	((void)(TRACING(req) && trace(req, res, __VA_ARGS__)))
extern int	trace(idmap_mapping *req, idmap_id_res *res, char *fmt, ...);

typedef idmap_retcode (*update_list_res_cb)(void *, const char **, uint64_t);
typedef int (*list_svc_cb)(void *, int, char **, char **);

extern void	idmap_prog_1(struct svc_req *, register SVCXPRT *);
extern void	idmapdlog(int, const char *, ...);
extern int	init_mapping_system();
extern void	fini_mapping_system();
extern void	print_idmapdstate();
extern int	create_directory(const char *, uid_t, gid_t);
extern int	load_config();
extern void	reload_ad();
extern void	idmap_init_tsd_key(void);
extern void	degrade_svc(int, const char *);
extern void	restore_svc(void);


extern int		init_dbs();
extern void		fini_dbs();
extern idmap_retcode	get_db_handle(sqlite **);
extern idmap_retcode	get_cache_handle(sqlite **);
extern idmap_retcode	sql_exec_no_cb(sqlite *, const char *, char *);
extern idmap_retcode	add_namerule(sqlite *, idmap_namerule *);
extern idmap_retcode	rm_namerule(sqlite *, idmap_namerule *);
extern idmap_retcode	flush_namerules(sqlite *);

extern char 		*tolower_u8(const char *);

extern idmap_retcode	gen_sql_expr_from_rule(idmap_namerule *, char **);
extern idmap_retcode	validate_list_cb_data(list_cb_data_t *, int,
				char **, int, uchar_t **, size_t);
extern idmap_retcode	process_list_svc_sql(sqlite *, const char *, char *,
				uint64_t, int, list_svc_cb, void *);
extern idmap_retcode	sid2pid_first_pass(lookup_state_t *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	sid2pid_second_pass(lookup_state_t *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	pid2sid_first_pass(lookup_state_t *,
				idmap_mapping *, idmap_id_res *, int);
extern idmap_retcode	pid2sid_second_pass(lookup_state_t *,
				idmap_mapping *, idmap_id_res *, int);
extern idmap_retcode	update_cache_sid2pid(lookup_state_t *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	update_cache_pid2sid(lookup_state_t *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	get_u2w_mapping(sqlite *, sqlite *, idmap_mapping *,
				idmap_mapping *, int);
extern idmap_retcode	get_w2u_mapping(sqlite *, sqlite *, idmap_mapping *,
				idmap_mapping *);
extern idmap_retcode	load_cfg_in_state(lookup_state_t *);
extern void		cleanup_lookup_state(lookup_state_t *);

extern idmap_retcode	ad_lookup_batch(lookup_state_t *,
				idmap_mapping_batch *, idmap_ids_res *);
extern idmap_retcode	lookup_name2sid(sqlite *, const char *, const char *,
				int, char **, char **, char **,
				idmap_rid_t *, idmap_id_type *,
				idmap_mapping *, int);
extern idmap_retcode	lookup_wksids_name2sid(const char *, const char *,
				char **, char **, char **, idmap_rid_t *,
				idmap_id_type *);
extern idmap_retcode	idmap_cache_flush(idmap_flush_op);

extern const wksids_table_t *find_wksid_by_pid(posix_id_t pid, int is_user);
extern const wksids_table_t *find_wksid_by_sid(const char *sid, int rid,
    idmap_id_type type);
extern const wksids_table_t *find_wksid_by_name(const char *name,
    const char *domain, idmap_id_type type);
extern const wksids_table_t *find_wk_by_sid(char *sid);

#ifdef __cplusplus
}
#endif

#endif /* _IDMAPD_H */
