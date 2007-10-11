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

#ifndef _IDMAPD_H
#define	_IDMAPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <rpc/rpc.h>
#include <synch.h>
#include <thread.h>
#include <libintl.h>
#include <strings.h>
#include <sqlite/sqlite.h>
#include <inttypes.h>
#include "idmap_prot.h"
#include "adutils.h"
#include "idmap_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* States a server can be in wrt request */
#define	_IDLE	0
#define	_SERVED	1

#define	CHECK_NULL(s)	s?s:"null"

#define	SENTINEL_PID	UINT32_MAX

extern int _rpcsvcstate;	/* set when a request is serviced */
extern int _rpcsvccount;	/* number of requests being serviced */
extern mutex_t _svcstate_lock;	/* lock for _rpcsvcstate, _rpcsvccount */

/*
 * Global state of idmapd daemon.
 */
#define	IDMAP_MAX_NAME_LEN	512
typedef struct idmapd_state {
	rwlock_t	rwlk_cfg;		/* config lock */
	idmap_cfg_t	*cfg;			/* config */
	bool_t		daemon_mode;		/* daemon mode? yes/no */
	char		hostname[MAX_NAME_LEN];	/* my hostname */
	char	domainname[IDMAP_MAX_NAME_LEN];	/* my domain */
	uid_t		next_uid;
	gid_t		next_gid;
	uid_t		limit_uid;
	gid_t		limit_gid;
	int		new_eph_db;	/* was the ephem ID db [re-]created? */
	ad_t		*ad;
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
	idmap_query_state_t	*ad_lookup;
	int			ad_nqueries;
	uint_t			curpos;
	hashentry_t		*sid_history;
	uint_t			sid_history_size;
	idmap_mapping_batch	*batch;
	idmap_ids_res		*result;
} lookup_state_t;

typedef struct list_cb_data {
	void		*result;
	uint64_t	next;
	uint64_t	len;
	uint64_t	limit;
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
	const char	*winname;
	int		is_user;
	uid_t		pid;
	int		direction;
} wksids_table_t;


#define	_IDMAP_F_DONE		0x00000000
#define	_IDMAP_F_S2N_CACHE	0x00000001
#define	_IDMAP_F_S2N_AD		0x00000002
#define	_IDMAP_F_EXP_EPH_UID	0x00000004
#define	_IDMAP_F_EXP_EPH_GID	0x00000010

#define	SIZE_INCR	5
#define	MAX_TRIES	5
#define	IDMAP_DBDIR	"/var/idmap"
#define	IDMAP_CACHEDIR	"/var/run/idmap"
#define	IDMAP_DBNAME	IDMAP_DBDIR "/idmap.db"
#define	IDMAP_CACHENAME	IDMAP_CACHEDIR "/idmap.db"
#define	IDMAP_CACHENAME	IDMAP_CACHEDIR "/idmap.db"

#define	EMPTY_STRING(str)	(str == NULL || *str == 0)

typedef idmap_retcode (*update_list_res_cb)(void *, const char **, uint64_t);
typedef int (*list_svc_cb)(void *, int, char **, char **);

extern void	idmap_prog_1(struct svc_req *, register SVCXPRT *);
extern void	idmapdlog(int, const char *, ...);
extern int	init_mapping_system();
extern void	fini_mapping_system();
extern void	print_idmapdstate();
extern int	create_directory(const char *, uid_t, gid_t);
extern int	load_config();
extern int	idmap_init_tsd_key(void);


extern int		init_dbs();
extern void		fini_dbs();
extern idmap_retcode	get_db_handle(sqlite **);
extern idmap_retcode	get_cache_handle(sqlite **);
extern idmap_retcode	sql_exec_no_cb(sqlite *, char *);
extern idmap_retcode	add_namerule(sqlite *, idmap_namerule *);
extern idmap_retcode	rm_namerule(sqlite *, idmap_namerule *);
extern idmap_retcode	flush_namerules(sqlite *, bool_t);

extern idmap_retcode	gen_sql_expr_from_utf8str(const char *,
				const char *, const char *,
				char *, const char *,
				char **);
extern idmap_retcode	validate_list_cb_data(list_cb_data_t *, int,
				char **, int, uchar_t **, size_t);
extern idmap_retcode	process_list_svc_sql(sqlite *, char *, uint64_t,
				list_svc_cb, void *);
extern idmap_retcode	sid2pid_first_pass(lookup_state_t *, sqlite *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	sid2pid_second_pass(lookup_state_t *, sqlite *,
				sqlite *, idmap_mapping *, idmap_id_res *);
extern idmap_retcode	pid2sid_first_pass(lookup_state_t *, sqlite *,
				sqlite *, idmap_mapping *, idmap_id_res *,
				int, int);
extern idmap_retcode	update_cache_sid2pid(lookup_state_t *, sqlite *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	update_cache_pid2sid(lookup_state_t *, sqlite *,
				idmap_mapping *, idmap_id_res *);
extern idmap_retcode	get_u2w_mapping(sqlite *, sqlite *, idmap_mapping *,
				idmap_mapping *, int);
extern idmap_retcode	get_w2u_mapping(sqlite *, sqlite *, idmap_mapping *,
				idmap_mapping *);

extern idmap_retcode	lookup_win_batch_sid2name(lookup_state_t *,
				idmap_mapping_batch *, idmap_ids_res *);


#ifdef __cplusplus
}
#endif

#endif /* _IDMAPD_H */
