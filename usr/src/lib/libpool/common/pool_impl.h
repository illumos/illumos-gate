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

#ifndef	_POOL_IMPL_H
#define	_POOL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains the definitions of types and supporting
 * functions to implement the libpool generic data manipulation
 * facility.
 *
 * libpool is designed so that the data representation/storage method
 * used may be easily replaced without affecting core functionality.
 * A libpool configuration is connected to a particular data
 * representation/storage "driver" via the pool_connection_t
 * type. When a configuration is opened (see pool_conf_open) the
 * libpool implementation allocates a specific data manipulation type
 * and initialises it. For instance, see pool_xml_connection_alloc.
 *
 * This function represents a cross-over point and all routines used
 * for data representation/storage are controlled by the type of
 * allocated connection.
 *
 * Currently, there are two implemented methods of access. Data may be
 * retrieved from the kernel, using the pool_knl_connection_t
 * function. This implementation relies on a private interface
 * provided by a driver, /dev/pool, and presents data retrieved from
 * the kernel via the standard libpool interface. Alternatively, data
 * may be retrieved from an XML file, via pool_xml_connection_t, and
 * presented through the standard libpool interface. For details of
 * these two implementations, see pool_kernel_impl.h and
 * pool_xml_impl.h.
 *
 * In addition to defining a specific connection type for a desired
 * data representation/storage medium, several other structures must
 * be defined to allow manipulation of configuration elements.
 *
 * Configuration elements are represented as pool_elem_t instances, or
 * as sub-types of this generic type (such as pool_t, which represents
 * a pool element) with groups (or sets) of these instances available
 * for manipulation via the pool_result_set_t type.
 *
 * For more information on the implementation of these types, read the
 * detailed comments above each structure definition.
 */

/*
 * The pool_elem_t is used to represent a configuration element.The
 * class of the element is stored within the structure along with a
 * pointer to the containing configuration and a pointer to the
 * element's specific subtype.
 *
 * The function pointers are initialised when the element is allocated
 * to use the specific functions provided by the concrete data
 * representation.
 *
 * The full set of operations that can be performed on an element
 * which require special treatment from the data
 * representation/storage medium are defined.
 */
struct pool_elem {
	pool_conf_t *pe_conf;				/* Configuration */
	pool_elem_class_t pe_class;			/* Element class */
	pool_resource_elem_class_t pe_resource_class;	/* Resource class */
	pool_component_elem_class_t pe_component_class;	/* Component class */
	struct pool_elem *pe_pair;			/* Static pair */
	pool_value_class_t (*pe_get_prop)(const pool_elem_t *, const char *,
	    pool_value_t *);
	int (*pe_put_prop)(pool_elem_t *, const char *, const pool_value_t *);
	int (*pe_rm_prop)(pool_elem_t *, const char *);
	pool_value_t **(*pe_get_props)(const pool_elem_t *, uint_t *);
	int (*pe_remove)(pool_elem_t *);
	pool_elem_t *(*pe_get_container)(const pool_elem_t *);
	int (*pe_set_container)(pool_elem_t *, pool_elem_t *);
};

/*
 * libpool performs many operations against a pool_elem_t. This basic
 * type is extended to provide specific functionality and type safety
 * for each of the different types of element supported by
 * libpool. There are four types of element:
 * - pool_system_t, represents an entire configuration
 * - pool_t, represents a single pool
 * - pool_resource_t, represents a single resource
 * - pool_component_t, represents a single resource component
 *
 * pool_system_t is an internal structure, the other structures are
 * externally visible and form a major part of the libpool interface.
 */
typedef struct pool_system
{
	pool_elem_t ps_elem;
	void *pe_pad1;
	void *pe_pad2;
} pool_system_t;

struct pool
{
	pool_elem_t pp_elem;
	/*
	 * Specific to pool_t
	 */
	int (*pp_associate)(pool_t *, const pool_resource_t *);
	int (*pp_dissociate)(pool_t *, const pool_resource_t *);
};

struct pool_resource
{
	pool_elem_t pr_elem;
	/*
	 * Specific to pool_resource_t
	 */
	int (*pr_is_system)(const pool_resource_t *);
	int (*pr_can_associate)(const pool_resource_t *);
};

struct pool_component
{
	pool_elem_t pc_elem;
	void *pe_pad1;
	void *pe_pad2;
};

/*
 * The pool_result_set_t is used to represent a collection (set) of
 * configuration elements. The configuration to which this result set
 * applies is stored along with an indicator as to whether the result
 * set is still in use.
 *
 * The function pointers are initialised when the element is allocated
 * to use the specific functions provided by the concrete data
 * representation.
 *
 * The full set of operations that can be performed on an element
 * which require special treatment from the data
 * representation/storage medium are defined.
 */
typedef struct pool_result_set {
	pool_conf_t *prs_conf;				/* Configuration */
	int prs_active;					/* Query active? */
	int prs_index;					/* Result Index */
	pool_elem_t *(*prs_next)(struct pool_result_set *);
	pool_elem_t *(*prs_prev)(struct pool_result_set *);
	pool_elem_t *(*prs_first)(struct pool_result_set *);
	pool_elem_t *(*prs_last)(struct pool_result_set *);
	int (*prs_set_index)(struct pool_result_set *, int);
	int (*prs_get_index)(struct pool_result_set *);
	int (*prs_close)(struct pool_result_set *);
	int (*prs_count)(struct pool_result_set *);
} pool_result_set_t;

/*
 * The pool_connection_t is used to represent a connection between a
 * libpool configuration and a particular implementation of the
 * libpool interface in a specific data representation/storage medium,
 * e.g. XML.
 *
 * The name of the storage medium is stored along with the type of the
 * data store.
 *
 * The function pointers are initialised when the element is allocated
 * to use the specific functions provided by the concrete data
 * representation.
 *
 * The full set of operations that can be performed on an element
 * which require special treatment from the data
 * representation/storage medium are defined.
 */
typedef struct pool_connection {
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
	    const pool_elem_t *, const char *, pool_elem_class_t,
	    pool_value_t **);
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
} pool_connection_t;

/*
 * pool_conf represents a resource management configuration. The
 * configuration location is stored in the pc_location member with the
 * state of the configuration stored in pc_state.
 *
 * The pc_prov member provides data representation/storage abstraction
 * for the configuration since all access to data is performed through
 * this member.
 */
struct pool_conf {
	const char *pc_location;			/* Location */
	pool_connection_t *pc_prov;			/* Data Provider */
	pool_conf_state_t pc_state;			/* State */
};

/*
 * Convert a pool_elem_t to it's appropriate sub-type.
 */
extern pool_system_t	*pool_conf_system(const pool_conf_t *);
extern pool_system_t	*pool_elem_system(const pool_elem_t *);
extern pool_t		*pool_elem_pool(const pool_elem_t *);
extern pool_resource_t	*pool_elem_res(const pool_elem_t *);
extern pool_component_t	*pool_elem_comp(const pool_elem_t *);

/*
 * Convert a pool_system_t to a pool_elem_t.
 */
extern pool_elem_t	*pool_system_elem(const pool_system_t *);

/*
 * Get/Set an element's "pair" element. A pair element is a temporary
 * association at commit between an element in the dynamic
 * configuration and an element in the static configuration. This
 * relationship is stored in the pe_pair member of the element.
 */
extern pool_elem_t	*pool_get_pair(const pool_elem_t *);
extern void		pool_set_pair(pool_elem_t *, pool_elem_t *);

/*
 * Result Set Manipulation
 */
extern pool_elem_t	*pool_rs_next(pool_result_set_t *);
extern pool_elem_t	*pool_rs_prev(pool_result_set_t *);
extern pool_elem_t	*pool_rs_first(pool_result_set_t *);
extern pool_elem_t	*pool_rs_last(pool_result_set_t *);
extern int		pool_rs_count(pool_result_set_t *);
extern int		pool_rs_get_index(pool_result_set_t *);
extern int		pool_rs_set_index(pool_result_set_t *, int);
extern int		pool_rs_close(pool_result_set_t *);

/*
 * General Purpose Query
 */
extern pool_result_set_t *pool_exec_query(const pool_conf_t *,
    const pool_elem_t *, const char *, pool_elem_class_t, pool_value_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _POOL_IMPL_H */
