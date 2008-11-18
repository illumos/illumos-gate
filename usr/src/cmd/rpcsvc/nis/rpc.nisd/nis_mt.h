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


#ifndef	_NIS_MT_H
#define	_NIS_MT_H

#include <pthread.h>
#include <synch.h>
#include <sys/types.h>
#include <stdlib.h>
#include <rpcsvc/nis_callback.h>
#include <rpcsvc/yp_prot.h>

#include <nisdb_rw.h>
#include <nis_hashitem.h>

/* RW locks */
USERWLOCK(upd_list);		/* nis_main.c */
USERWLOCK(ping_list);		/* nis_main.c */
USERWLOCK(nisopstats);		/* nis_service.c, nis_xx_proc.c */
USERWLOCK(table_cache);		/* nis_db.c */
USERWLOCK(dircachestats);	/* nis_subr_proc.c */
USERWLOCK(translog);		/* nis_log_common.c, nis_log_svc.c */

/* Functions */
extern int		msleep(ulong_t);
extern void		mark_activity(void);
extern void		*servloop(void *);
extern void		*callback_thread(void *);
extern void		*dumpsvc_thread(void *);

extern void		wakeup_servloop(void);
extern time_t		updateBatchingTimeout(void);
extern void		setPingWakeup(time_t);

/*
 * MAXCLOCKS normally in libnsl/nis/gen/nis_local.h, but we roll our own
 * thread-specific clocks.
 */
#define		MAXCLOCKS	16

#define		MAXRAGS		1024
/* Probably don't need MAXRAGS for a single thread. MAXRAGS_THR is a guess */
#define		MAXRAGS_THR	(MAXRAGS/16)

/* Keep track of allocated rag blocks */
typedef struct cleanupblockstruct {
	struct cleanupblockstruct	*next;
} cleanupblock_t;

/* Statistics structure from nis_subr_proc.c */
typedef struct {
	int	successes;
	int	errors;
	int	ticks;
	ulong_t	utime;
} repl_stats_t;

/* yp_all() response structure from yp_ns_proc.c */
typedef char *string_t;
struct ypresp_all {
	long		status;
	string_t	table_name;
	nis_name	princp;
	int		key_column_ndx;
	nis_object *table_zobj;
};

/* Thread-specific data */
typedef struct {
	struct timeval		clocks[MAXCLOCKS];
	struct cleanup		*looseends;
	struct cleanup		*rags[MAXRAGS_THR];
	struct cleanup		*free_rags;
	uint32_t		cleanup_tag;
	cleanupblock_t		*ragblocks;
	nis_name		invalid_directory;
	struct nis_sdata	censor_object_buf;
	struct nis_sdata	modify_entry_buf;
	struct nis_sdata	__ibops_buf;
	nis_db_result		db_add_res;
	nis_db_result		db_remove_res;
	struct nis_sdata	local_buf__get_xdr_buf;
	struct nis_sdata	local_buf__get_string_buf;
	struct nis_sdata	local_buf__get_entry_col;
	struct nis_sdata	local_buf__get_table_col;
	struct nis_sdata	local_buf__get_attrs;
	repl_stats_t		repl_stats;
	uint_t			nis_cptime_svc_res;
	nis_error		nis_mkdir_svc_result;
	nis_error		nis_rmdir_svc_result;
	char			yp_ns_proc_record[YPMAXRECORD];
	char			yp_ns_proc_keyval[YPMAXRECORD];
	bool_t			ypproc_domain_svc_isserved;
	bool_t			ypproc_domain_nonack_svc_isserved;
	struct ypresp_master	ypproc_master_svc_resp;
	char			ypproc_master_svc_masterbuf[YPMAXPEER];
	struct ypresp_val	ypproc_match_svc_resp;
	struct ypresp_key_val	ypproc_first_svc_resp;
	struct ypresp_key_val	ypproc_next_svc_resp;
	struct ypresp_all	ypproc_all_svc_resp;
	struct ypresp_maplist	ypproc_maplist_svc_maplist;
	char			xdr_ypresp_all_short_tblnm[YPMAXMAP];
	char			*best_host_address_best_address;
	char			getcaller_inet_buf[256];
	char			map2table_tbl[YPMAXMAP];
	char			map2table_col[NIS_MAXATTRNAME];
	bool_t			nis_callback_svc_res;
} nis_tsd_t;

extern nis_tsd_t	*__nis_get_tsd(void);
extern void		__nis_thread_cleanup(nis_tsd_t *);
extern void		__nis_free_items_mt(nis_tsd_t *);

/* Arguments for thread entry point functions */
typedef struct {
	nis_fn_result	*fnr;
	nis_object	*ib_obj;
	nis_attr	a[NIS_MAXATTR];
	nis_server	*nserver;
	int		na;
	int		nm;
	int		all_read;
	char		pname[1024];
	cback_data	cbarg;
	CLIENT		*cback;
	char		cbhostname[NIS_MAXNAMELEN];
	char		ibr_name[NIS_MAXNAMELEN];
} callback_thread_arg_t;

typedef struct {
	char		da_dir[1024];
	char		pname[1024];
	CLIENT		*cback;
	ulong_t		ttime;
} dumpsvc_thread_arg_t;

#endif	/* _NIS_MT_H */
