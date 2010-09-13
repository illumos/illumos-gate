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

#ifndef	_SES_IMPL_H
#define	_SES_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <alloca.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>

#include <scsi/libscsi.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>

#define	LIBSES_ERRMSGLEN	512

#define	LIBSES_DEFAULT_PLUGINDIR 	"/usr/lib/scsi/plugins/ses"
#define	LIBSES_PLUGIN_FRAMEWORK		"framework"
#define	LIBSES_PLUGIN_VENDOR		"vendor"

#define	LIBSES_PLUGIN_EXT	".so"

struct ses_plugin {
	struct ses_plugin *sp_next;	/* next plugin in list */
	struct ses_plugin *sp_prev;	/* previous plugin in list */
	uint64_t sp_priority;		/* plugin priority */
	struct ses_target *sp_target;	/* corresponding target */
	void *sp_object;		/* shared object */
	void *sp_data;			/* module-specific data */
	boolean_t sp_initialized;	/* successfully initialized */
	ses_pagedesc_t *sp_pages;	/* pages */
	int (*sp_init)(ses_plugin_t *);	/* plugin init */
	void (*sp_fini)(ses_plugin_t *); /* plugin fini */
	int (*sp_node_parse)(ses_plugin_t *, ses_node_t *); /* parse node */
	int (*sp_node_ctl)(ses_plugin_t *, ses_node_t *, const char *,
	    nvlist_t *);		/* node control */
};

struct ses_target {
	libscsi_hdl_t *st_scsi_hdl;
	libscsi_target_t *st_target;
	struct ses_plugin *st_plugin_first;
	struct ses_plugin *st_plugin_last;
	struct ses_snap *st_snapshots;
	boolean_t st_closescsi;
	boolean_t st_truncate;
	pthread_mutex_t st_lock;
};

/*
 * Maximum number of snapshot retries triggered by generation count changes
 */
#define	LIBSES_MAX_GC_RETRIES	10

/*
 * Maximum number of Enclosure Busy retries
 */
#define	LIBSES_MAX_BUSY_RETRIES	3

typedef struct ses_snap_page {
	ses2_diag_page_t ssp_num;
	boolean_t ssp_control;
	boolean_t ssp_initialized;
	size_t ssp_alloc;
	size_t ssp_len;
	void *ssp_page;
	char *ssp_mmap_base;
	size_t ssp_mmap_len;
	struct ses_snap_page *ssp_next;
	struct ses_snap_page *ssp_unique;
} ses_snap_page_t;

struct ses_snap {
	struct ses_target *ss_target;
	uint32_t ss_generation;
	hrtime_t ss_time;
	struct ses_node *ss_root;
	size_t ss_n_elem;
	ses_snap_page_t *ss_pages;
	size_t ss_n_nodes;
	struct ses_node **ss_nodes;
	struct ses_snap *ss_next;
	struct ses_snap *ss_prev;
	uint32_t ss_refcnt;
};

struct ses_node {
	ses_node_type_t sn_type;
	uint64_t sn_rootidx;	/* Relative index for enclosure/aggregate */
	size_t sn_id;		/* Unique global ID */
	uint64_t sn_enc_num;
	struct ses_snap *sn_snapshot;
	struct ses_node *sn_parent;
	struct ses_node *sn_next_sibling;
	struct ses_node *sn_prev_sibling;
	struct ses_node *sn_first_child;
	struct ses_node *sn_last_child;
	nvlist_t *sn_props;
};

extern int ses_fill_snap(ses_snap_t *);
extern void ses_node_teardown(ses_node_t *);
extern ses_snap_page_t *ses_snap_find_page(ses_snap_t *, ses2_diag_page_t,
    boolean_t);
extern ses_snap_page_t *ses_snap_ctl_page(ses_snap_t *,
    ses2_diag_page_t, size_t, boolean_t);
extern int ses_snap_do_ctl(ses_snap_t *);

extern int ses_libscsi_error(libscsi_hdl_t *, const char *, ...);
extern int ses_scsi_error(libscsi_action_t *, const char *, ...);

extern int ses_plugin_load(ses_target_t *);
extern void ses_plugin_unload(ses_target_t *);

extern ses_pagedesc_t *ses_get_pagedesc(ses_target_t *, int, ses_pagetype_t);
extern int ses_fill_node(ses_node_t *);

extern int enc_parse_ed(ses2_ed_impl_t *, nvlist_t *);
extern int enc_parse_td(ses2_td_hdr_impl_t *, const char *, nvlist_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SES_IMPL_H */
