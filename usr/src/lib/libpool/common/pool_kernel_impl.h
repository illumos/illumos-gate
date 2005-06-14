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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_POOL_KERNEL_IMPL_H
#define	_POOL_KERNEL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains the definitions of types and supporting
 * functions to implement the libpool kernel specific data
 * manipulation facility.
 *
 * For more information on the libpool generic data manipulation
 * facility, look at pool_impl.h.
 *
 * The central types for the generic data representation/storage
 * facility are here enhanced to provide additional kernel specific
 * information.
 */

/*
 * pool_knl_elem_t is the kernel specific representation of the
 * pool_elem_t structure.
 */
typedef struct pool_knl_elem {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pke_elem;
	void *pke_pad1;
	void *pke_pad2;
	/*
	 * Common to pool_knl_elem_t
	 */
	nvlist_t *pke_properties;			/* Properties nvlist */
	struct pool_knl_elem *pke_parent;		/* Element parent */
	uint64_t pke_ltime;				/* Library timestamp */
} pool_knl_elem_t;

typedef pool_knl_elem_t pool_knl_system_t;

typedef struct pool_knl_resource {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pke_elem;
	/*
	 * Specific to pool_resource_t
	 */
	int (*pr_is_system)(const pool_resource_t *);
	int (*pr_can_associate)(const pool_resource_t *);
	/*
	 * Common to pool_knl_elem_t
	 */
	nvlist_t *pke_properties;			/* Properties nvlist */
	struct pool_knl_elem *pke_parent;		/* Element parent */
	uint64_t pke_ltime;				/* Library timestamp */
} pool_knl_resource_t;

typedef pool_knl_elem_t pool_knl_component_t;

typedef struct pool_knl_pool {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pke_elem;
	/*
	 * Specific to pool_t
	 */
	int (*pp_associate)(pool_t *, const pool_resource_t *);
	int (*pp_dissociate)(pool_t *, const pool_resource_t *);
	/*
	 * Common to pool_knl_elem_t
	 */
	nvlist_t *pke_properties;			/* Properties nvlist */
	struct pool_knl_elem *pke_parent;		/* Element parent */
	uint64_t pke_ltime;				/* Library timestamp */
	/*
	 * Specific to pool_knl_pool_t
	 */
	pool_knl_resource_t *pkp_assoc[4];		/* Pool resources */
} pool_knl_pool_t;

/*
 * pool_knl_result_set_t is the kernel specific representation of the
 * pool_result_set_t structure.
 *
 */
typedef struct pool_knl_result_set {
	const pool_conf_t *prs_conf;			/* Configuration */
	int prs_active;					/* Query active? */
	int prs_index;					/* Result Index */
	pool_elem_t *(*prs_next)(pool_result_set_t *);
	pool_elem_t *(*prs_prev)(pool_result_set_t *);
	pool_elem_t *(*prs_first)(pool_result_set_t *);
	pool_elem_t *(*prs_last)(pool_result_set_t *);
	int (*prs_set_index)(pool_result_set_t *, int);
	int (*prs_get_index)(pool_result_set_t *);
	int (*prs_close)(pool_result_set_t *);
	int (*prs_count)(pool_result_set_t *);
	/*
	 * End of common part
	 */
	pool_knl_elem_t **pkr_list;			/* Result members */
	int pkr_count;					/* Result set count */
	int pkr_size;					/* Result set size */
} pool_knl_result_set_t;

/*
 * pool_knl_connection_t is the kernel specific representation of the
 * pool_connection_t structure.
 *
 */
typedef struct pool_knl_connection {
	const char *pc_name;				/* Provider name */
	int pc_store_type;				/* Datastore type */
	int pc_oflags;					/* Open flags */
	int (*pc_close)(pool_conf_t *);
	int (*pc_validate)(const pool_conf_t *, pool_valid_level_t);
	int (*pc_commit)(pool_conf_t *);
	int (*pc_export)(const pool_conf_t *, const char *,
	    pool_export_format_t);
	int (*pc_rollback)(pool_conf_t *);
	pool_result_set_t *(*pc_exec_query)(const pool_conf_t *,
	    const pool_elem_t *, const char *,
	    pool_elem_class_t, pool_value_t **);
	pool_elem_t *(*pc_elem_create)(pool_conf_t *, pool_elem_class_t,
	    pool_resource_elem_class_t, pool_component_elem_class_t);
	int (*pc_remove)(pool_conf_t *);
	int (*pc_res_xfer)(pool_resource_t *, pool_resource_t *, uint64_t);
	int (*pc_res_xxfer)(pool_resource_t *, pool_resource_t *,
	    pool_component_t **);
	char *(*pc_get_binding)(pool_conf_t *, pid_t);
	int (*pc_set_binding)(pool_conf_t *, const char *, idtype_t, id_t);
	char *(*pc_get_resource_binding)(pool_conf_t *,
	    pool_resource_elem_class_t, pid_t);
	/*
	 * End of common part
	 */
	int pkc_fd;					/* Pool device */
	dict_hdl_t *pkc_elements;			/* Elements */
#if DEBUG
	dict_hdl_t *pkc_leaks;				/* Elements */
#endif	/* DEBUG */
	log_t *pkc_log;					/* Transaction log */
	hrtime_t pkc_ltime;				/* Snap updated */
	hrtime_t pkc_lotime;				/* Snap last updated */
} pool_knl_connection_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _POOL_KERNEL_IMPL_H */
